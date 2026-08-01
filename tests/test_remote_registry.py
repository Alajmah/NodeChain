"""Tests for Remote Registry Foundation (v2.0.0).

Tests cover all 14 acceptance criteria:

  AC1:  RemoteRegistryClient exists
  AC2:  Protocol v1 endpoints defined
  AC3:  CLI command install-remote
  AC4:  Registry metadata verification (digest, protocol, keys)
  AC5:  Package metadata verification
  AC6:  Artifact verification (SHA-256, size, safe extraction)
  AC7:  Trust store purposes extended
  AC8:  Installed packages get remote_untrusted
  AC9:  remote_untrusted maps to strongest sandbox
  AC10: Install receipt with full provenance
  AC11: Evidence index supports receipts
  AC12: Dashboard integration
  AC13: Negative tests (12 attack scenarios)
  AC14: Windows/Linux green (implicit)
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ── Test Fixtures ───────────────────────────────────────────────────────────


class MockTransport:
    """Mock HTTP transport for testing without network."""

    def __init__(self):
        self.routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def add_route(self, path: str, status: int, headers: dict[str, str], body: bytes):
        self.routes[path] = (status, headers, body)

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        # Match by suffix path
        for path, (status, headers, body) in self.routes.items():
            if url.endswith(path) or path in url:
                return status, headers, body
        return 404, {}, b'{"error": "not found"}'


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _make_registry_metadata() -> dict[str, Any]:
    """Create valid registry metadata."""
    from nodechain.sdk.remote_registry import RemoteRegistryMetadata
    meta = RemoteRegistryMetadata(
        schema_version="1.0",
        registry_id="test-registry-001",
        registry_name="Test Registry",
        registry_public_key="-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----",
        registry_public_key_fingerprint="abc123def456",
        supported_protocol_versions=("v1",),
        packages_base_url="https://registry.example.com",
    )
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "mock_signature"
    return meta.to_dict()


def _make_package_metadata(artifact_bytes: bytes) -> dict[str, Any]:
    """Create valid package metadata for given artifact."""
    from nodechain.sdk.remote_registry import RemotePackageMetadata
    meta = RemotePackageMetadata(
        schema_version="1.0",
        package_id="test_remote_pkg",
        version="1.0.0",
        artifact_digest=_sha256_bytes(artifact_bytes),
        artifact_size=len(artifact_bytes),
        manifest_digest="manifest_sha256",
        certification_digest="cert_sha256",
        publisher_public_key="-----BEGIN PUBLIC KEY-----\nMOCK_PUB\n-----END PUBLIC KEY-----",
        publisher_fingerprint="pub_fp_123",
        description="Test remote package",
        nodes=["TestNode"],
        capabilities=["read_only"],
        sandbox_profile="hardened_untrusted",
    )
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "publisher_sig"
    return meta.to_dict()


def _make_safe_tar(files: dict[str, str]) -> bytes:
    """Create a safe tar archive in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── AC1: RemoteRegistryClient ───────────────────────────────────────────────

class TestAC1RemoteRegistryClient:
    """AC1: RemoteRegistryClient exists and is functional."""

    def test_client_exists(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient
        client = RemoteRegistryClient(base_url="https://registry.example.com")
        assert client.base_url == "https://registry.example.com/"

    def test_client_rejects_non_tls_by_default(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RemoteRegistryError
        with pytest.raises(RemoteRegistryError, match="TLS required"):
            RemoteRegistryClient(base_url="http://registry.example.com")

    def test_client_allows_non_tls_when_insecure(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient
        client = RemoteRegistryClient(base_url="http://localhost:8080", require_tls=False)
        assert client.require_tls is False

    def test_client_defaults(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, DEFAULT_TIMEOUT_SECONDS
        client = RemoteRegistryClient(base_url="https://r.example.com")
        assert client.timeout == DEFAULT_TIMEOUT_SECONDS
        assert client.retry_count == 2


# ── AC2: Protocol v1 Endpoints ──────────────────────────────────────────────

class TestAC2ProtocolV1:
    """AC2: Remote registry protocol v1 defined."""

    def test_protocol_version(self):
        from nodechain.sdk.remote_registry import REMOTE_REGISTRY_PROTOCOL_VERSION
        assert REMOTE_REGISTRY_PROTOCOL_VERSION == "v1"

    def test_well_known_path(self):
        from nodechain.sdk.remote_registry import WELL_KNOWN_PATH
        assert WELL_KNOWN_PATH == "/.well-known/nodechain-registry.json"

    def test_package_metadata_path(self):
        from nodechain.sdk.remote_registry import PACKAGE_METADATA_PATH
        path = PACKAGE_METADATA_PATH.format(package_id="pkg", version="1.0.0")
        assert path == "/packages/pkg/versions/1.0.0.json"

    def test_artifact_path(self):
        from nodechain.sdk.remote_registry import ARTIFACT_PATH
        path = ARTIFACT_PATH.format(package_id="pkg", version="1.0.0")
        assert path == "/packages/pkg/versions/1.0.0/artifact"


# ── AC3: CLI Command ────────────────────────────────────────────────────────

class TestAC3CLI:
    """AC3: nodechain registry install-remote exists."""

    def test_command_exists(self):
        from nodechain.cli.main import cli
        registry = cli.commands["registry"]
        assert "install-remote" in registry.commands

    def test_command_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "install-remote", "--help"])
        assert result.exit_code == 0
        assert "remote" in result.output.lower()

    def test_command_requires_args(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "install-remote"])
        assert result.exit_code != 0  # Missing required argument


# ── AC4: Registry Metadata Verification ─────────────────────────────────────

class TestAC4RegistryMetadata:
    """AC4: Registry metadata verification."""

    def test_metadata_roundtrip(self):
        from nodechain.sdk.remote_registry import RemoteRegistryMetadata
        data = _make_registry_metadata()
        meta = RemoteRegistryMetadata.from_dict(data)
        assert meta.registry_id == "test-registry-001"
        assert meta.verify_digest()

    def test_metadata_detects_tamper(self):
        from nodechain.sdk.remote_registry import RemoteRegistryMetadata
        data = _make_registry_metadata()
        data["registry_name"] = "Tampered"
        meta = RemoteRegistryMetadata.from_dict(data)
        assert not meta.verify_digest()

    def test_client_fetches_metadata(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient
        transport = MockTransport()
        reg_data = _make_registry_metadata()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {}, json.dumps(reg_data).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        meta = client.fetch_registry_metadata()
        assert meta.registry_id == "test-registry-001"

    def test_client_rejects_bad_digest(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RegistryMetadataError
        transport = MockTransport()
        data = _make_registry_metadata()
        data["metadata_digest"] = "tampered"
        transport.add_route("/.well-known/nodechain-registry.json", 200, {}, json.dumps(data).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(RegistryMetadataError, match="digest mismatch"):
            client.fetch_registry_metadata()

    def test_client_rejects_unsupported_protocol(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RegistryMetadataError
        from nodechain.sdk.remote_registry import RemoteRegistryMetadata
        transport = MockTransport()
        meta = RemoteRegistryMetadata(
            registry_id="bad",
            supported_protocol_versions=("v99",),
        )
        meta.metadata_digest = meta.compute_digest()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {}, json.dumps(meta.to_dict()).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(RegistryMetadataError, match="Unsupported protocol"):
            client.fetch_registry_metadata()


# ── AC5: Package Metadata Verification ──────────────────────────────────────

class TestAC5PackageMetadata:
    """AC5: Package metadata verification."""

    def test_package_metadata_roundtrip(self):
        from nodechain.sdk.remote_registry import RemotePackageMetadata
        artifact = b"test artifact"
        data = _make_package_metadata(artifact)
        meta = RemotePackageMetadata.from_dict(data)
        assert meta.package_id == "test_remote_pkg"
        assert meta.verify_digest()

    def test_package_metadata_detects_tamper(self):
        from nodechain.sdk.remote_registry import RemotePackageMetadata
        artifact = b"test artifact"
        data = _make_package_metadata(artifact)
        data["description"] = "Tampered"
        meta = RemotePackageMetadata.from_dict(data)
        assert not meta.verify_digest()

    def test_client_fetches_package_metadata(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient
        transport = MockTransport()
        artifact = _make_safe_tar({"node.py": "pass"})
        pkg_data = _make_package_metadata(artifact)
        pkg_path = f"/packages/test_remote_pkg/versions/1.0.0.json"
        transport.add_route(pkg_path, 200, {}, json.dumps(pkg_data).encode())
        transport.add_route("/.well-known/nodechain-registry.json", 200, {}, json.dumps(_make_registry_metadata()).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        meta = client.fetch_package_metadata("test_remote_pkg", "1.0.0")
        assert meta.package_id == "test_remote_pkg"
        assert meta.version == "1.0.0"

    def test_client_rejects_id_mismatch(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, PackageMetadataError
        transport = MockTransport()
        artifact = b"test"
        data = _make_package_metadata(artifact)
        data["package_id"] = "different_id"
        # Fix digest for the tampered version (but the ID check catches it)
        from nodechain.sdk.remote_registry import RemotePackageMetadata
        meta = RemotePackageMetadata.from_dict(data)
        meta.metadata_digest = meta.compute_digest()
        data = meta.to_dict()

        transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {}, json.dumps(data).encode())
        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(PackageMetadataError, match="Package ID mismatch"):
            client.fetch_package_metadata("test_remote_pkg", "1.0.0")


# ── AC6: Artifact Verification ──────────────────────────────────────────────

class TestAC6ArtifactVerification:
    """AC6: Artifact verification (SHA-256, size, safe extraction)."""

    def test_client_fetches_artifact(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient
        transport = MockTransport()
        artifact = _make_safe_tar({"node.py": "pass"})
        transport.add_route("/packages/pkg/versions/1.0.0/artifact", 200, {}, artifact)

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        result = client.fetch_artifact("pkg", "1.0.0")
        assert result == artifact

    def test_client_rejects_oversized_artifact(self):
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RemoteRegistryError
        transport = MockTransport()
        transport.add_route("/packages/pkg/versions/1.0.0/artifact", 200, {},
                            b"x" * 100)

        client = RemoteRegistryClient(
            base_url="https://registry.example.com",
            max_artifact_size=10,
            _transport=transport
        )
        with pytest.raises(RemoteRegistryError, match="too large"):
            client.fetch_artifact("pkg", "1.0.0")

    def test_verification_pipeline_all_pass(self):
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package, all_checks_passed
        )
        artifact = _make_safe_tar({"node.py": "pass"})
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))

        checks = verify_remote_package(reg, pkg, artifact)
        assert all_checks_passed(checks)
        assert len(checks) == 8

    def test_verification_detects_digest_mismatch(self):
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package
        )
        artifact = _make_safe_tar({"node.py": "pass"})
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))

        # Tamper with artifact
        bad_artifact = b"tampered" + artifact
        checks = verify_remote_package(reg, pkg, bad_artifact)
        digest_check = [c for c in checks if c.check == "artifact_digest"][0]
        assert not digest_check.passed

    def test_verification_detects_size_mismatch(self):
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package
        )
        artifact = _make_safe_tar({"node.py": "pass"})
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))
        # Mess up size
        pkg.artifact_size = 99999
        checks = verify_remote_package(reg, pkg, artifact)
        size_check = [c for c in checks if c.check == "artifact_size"][0]
        assert not size_check.passed


# ── AC7: Trust Store Purposes ───────────────────────────────────────────────

class TestAC7TrustStorePurposes:
    """AC7: Trust store purposes extended."""

    def test_remote_registry_signing_purpose(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "remote_registry_signing" in VALID_PURPOSES

    def test_remote_package_publishing_purpose(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "remote_package_publishing" in VALID_PURPOSES


# ── AC8: remote_untrusted Trust Level ───────────────────────────────────────

class TestAC8RemoteUntrusted:
    """AC8: Installed remote packages get remote_untrusted."""

    def test_receipt_has_remote_untrusted(self):
        from nodechain.sdk.remote_registry import RemoteInstallReceipt
        receipt = RemoteInstallReceipt()
        assert receipt.trust_level == "remote_untrusted"

    def test_registry_entry_has_remote_origin(self):
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            RemoteInstallReceipt, create_remote_registry_entry
        )
        artifact = b"test"
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))
        receipt = RemoteInstallReceipt(
            remote_url="https://r.example.com",
        ).finalize()

        entry = create_remote_registry_entry(pkg, reg, _sha256_bytes(artifact), receipt)
        assert entry["origin"] == "remote"
        assert entry["trust_level"] == "remote_untrusted"


# ── AC9: remote_untrusted → Strongest Sandbox ───────────────────────────────

class TestAC9SandboxMapping:
    """AC9: remote_untrusted maps to strongest available sandbox."""

    def test_mapping_exists(self):
        from nodechain.sdk.remote_readiness import resolve_sandbox_preset
        preset = resolve_sandbox_preset("remote_untrusted")
        assert preset in ("hardened_untrusted", "production_untrusted")


# ── AC10: Install Receipt ───────────────────────────────────────────────────

class TestAC10InstallReceipt:
    """AC10: Install receipt with full provenance."""

    def test_receipt_has_all_fields(self):
        from nodechain.sdk.remote_registry import RemoteInstallReceipt
        receipt = RemoteInstallReceipt(
            receipt_id="rec-001",
            remote_url="https://r.example.com",
            registry_id="reg-001",
            registry_metadata_digest="reg_digest",
            registry_signer_fingerprint="reg_fp",
            package_id="pkg",
            package_version="1.0.0",
            package_metadata_digest="pkg_digest",
            artifact_digest="art_digest",
            publisher_fingerprint="pub_fp",
        ).finalize()

        d = receipt.to_dict()
        assert d["remote_url"] == "https://r.example.com"
        assert d["registry_id"] == "reg-001"
        assert d["registry_metadata_digest"] == "reg_digest"
        assert d["package_metadata_digest"] == "pkg_digest"
        assert d["artifact_digest"] == "art_digest"
        assert d["publisher_fingerprint"] == "pub_fp"
        assert d["registry_signer_fingerprint"] == "reg_fp"
        assert d["verification_status"] == "verified"
        assert d["trust_level"] == "remote_untrusted"
        assert d["receipt_digest"] != ""

    def test_receipt_digest_verifies_integrity(self):
        from nodechain.sdk.remote_registry import RemoteInstallReceipt
        receipt = RemoteInstallReceipt(receipt_id="r1").finalize()
        d1 = receipt.compute_digest()

        # Tamper
        receipt.package_id = "tampered"
        d2 = receipt.compute_digest()
        assert d1 != d2


# ── AC11: Evidence Index ────────────────────────────────────────────────────

class TestAC11EvidenceIndex:
    """AC11: Evidence index supports remote install receipts."""

    def test_evidence_type_registered(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert "remote_install_receipt" in EVIDENCE_TYPES

    def test_receipt_detection(self):
        from nodechain.cli.evidence import _detect_artifact_type
        data = {
            "receipt_id": "r-001",
            "remote_url": "https://r.example.com",
            "artifact_digest": "abc123",
        }
        assert _detect_artifact_type(data) == "remote_install_receipt"

    def test_index_receipt(self, tmp_path):
        from nodechain.sdk.remote_registry import RemoteInstallReceipt, index_remote_install_receipt
        receipt = RemoteInstallReceipt(
            receipt_id="test-rec-001",
            remote_url="https://r.example.com",
        ).finalize()

        result = index_remote_install_receipt(receipt, evidence_dir=str(tmp_path))
        assert result["indexed"] is True
        receipt_file = tmp_path / "remote_install_test-rec-001.json"
        assert receipt_file.exists()


# ── AC12: Dashboard Integration ─────────────────────────────────────────────

class TestAC12Dashboard:
    """AC12: Dashboard shows remote registry status."""

    def test_dashboard_json_works(self):
        """Dashboard --json still works with remote registry code loaded."""
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json"])
        assert result.exit_code == 0


# ── AC13: Negative Tests ────────────────────────────────────────────────────

class TestAC13NegativeSmokes:
    """AC13: Negative tests for attack scenarios."""

    def _setup_mock_registry(self, tmp_path) -> tuple[MockTransport, bytes]:
        """Set up a valid mock registry for negative test overrides."""
        transport = MockTransport()
        artifact = _make_safe_tar({"node.py": "pass"})

        # Registry metadata
        reg_data = _make_registry_metadata()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(reg_data).encode())

        # Package metadata
        pkg_data = _make_package_metadata(artifact)
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                            json.dumps(pkg_data).encode())

        # Artifact
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                            artifact)

        return transport, artifact

    def test_neg_bad_tls_rejected(self):
        """Non-HTTPS rejected when TLS required."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RemoteRegistryError
        with pytest.raises(RemoteRegistryError, match="TLS required"):
            RemoteRegistryClient(base_url="http://registry.example.com")

    def test_neg_metadata_signature_invalid(self):
        """Tampered metadata digest is rejected."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RegistryMetadataError
        transport = MockTransport()
        data = _make_registry_metadata()
        data["metadata_digest"] = "tampered"
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(data).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(RegistryMetadataError, match="digest mismatch"):
            client.fetch_registry_metadata()

    def test_neg_digest_mismatch(self):
        """Artifact digest mismatch is detected."""
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package
        )
        artifact = _make_safe_tar({"node.py": "pass"})
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))

        checks = verify_remote_package(reg, pkg, b"different_bytes")
        digest_check = [c for c in checks if c.check == "artifact_digest"][0]
        assert not digest_check.passed

    def test_neg_version_mismatch(self):
        """Version mismatch in metadata is rejected."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, PackageMetadataError
        transport = MockTransport()
        artifact = b"test"
        data = _make_package_metadata(artifact)
        # Metadata says 1.0.0, but we serve it at the 2.0.0 endpoint
        # So client requests 2.0.0 but gets metadata for 1.0.0
        transport.add_route("/packages/test_remote_pkg/versions/2.0.0.json", 200, {},
                            json.dumps(data).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(PackageMetadataError, match="Version mismatch"):
            client.fetch_package_metadata("test_remote_pkg", "2.0.0")

    def test_neg_unsupported_protocol(self):
        """Unsupported protocol version is rejected."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RegistryMetadataError
        from nodechain.sdk.remote_registry import RemoteRegistryMetadata
        transport = MockTransport()
        meta = RemoteRegistryMetadata(supported_protocol_versions=("v99",))
        meta.metadata_digest = meta.compute_digest()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(meta.to_dict()).encode())

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(RegistryMetadataError, match="Unsupported protocol"):
            client.fetch_registry_metadata()

    def test_neg_oversized_package(self):
        """Oversized artifact is rejected."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, RemoteRegistryError
        transport = MockTransport()
        transport.add_route("/packages/pkg/versions/1.0.0/artifact", 200, {},
                            b"x" * 100)

        client = RemoteRegistryClient(
            base_url="https://registry.example.com",
            max_artifact_size=10,
            _transport=transport
        )
        with pytest.raises(RemoteRegistryError, match="too large"):
            client.fetch_artifact("pkg", "1.0.0")

    def test_neg_missing_publisher_key(self):
        """Missing publisher key fails verification."""
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package
        )
        artifact = b"test"
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))
        pkg.publisher_public_key = ""  # Missing

        checks = verify_remote_package(reg, pkg, artifact)
        key_check = [c for c in checks if c.check == "publisher_key_present"][0]
        assert not key_check.passed

    def test_neg_missing_registry_key(self):
        """Missing registry key fails verification."""
        from nodechain.sdk.remote_registry import (
            RemoteRegistryMetadata, RemotePackageMetadata,
            verify_remote_package
        )
        artifact = b"test"
        reg = RemoteRegistryMetadata.from_dict(_make_registry_metadata())
        reg.registry_public_key = ""  # Missing
        pkg = RemotePackageMetadata.from_dict(_make_package_metadata(artifact))

        checks = verify_remote_package(reg, pkg, artifact)
        key_check = [c for c in checks if c.check == "registry_signer_key_present"][0]
        assert not key_check.passed

    def test_neg_sandbox_downgrade_attempt(self):
        """remote_untrusted cannot upgrade to local_trusted."""
        from nodechain.sdk.remote_readiness import is_upgrade_allowed
        assert not is_upgrade_allowed("remote_untrusted", "local_trusted")
        assert not is_upgrade_allowed("remote_untrusted", "built_in")

    def test_neg_404_not_found(self):
        """404 from registry is handled."""
        from nodechain.sdk.remote_registry import RemoteRegistryClient, PackageMetadataError
        transport = MockTransport()
        transport.add_route("/packages/nonexistent/versions/1.0.0.json", 404, {}, b'{}')

        client = RemoteRegistryClient(
            base_url="https://registry.example.com", _transport=transport
        )
        with pytest.raises(PackageMetadataError, match="not found"):
            client.fetch_package_metadata("nonexistent", "1.0.0")

    def test_neg_full_install_with_bad_artifact(self, tmp_path, monkeypatch):
        """Full install flow fails with artifact digest mismatch."""
        from nodechain.sdk.remote_registry import install_remote_package
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        monkeypatch.setenv("NODECHAIN_REMOTE_INSTALL_DIR", str(tmp_path / "pkgs"))

        transport = MockTransport()
        # Valid registry + package metadata
        artifact_real = _make_safe_tar({"node.py": "pass"})
        reg_data = _make_registry_metadata()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(reg_data).encode())
        pkg_data = _make_package_metadata(artifact_real)
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                            json.dumps(pkg_data).encode())
        # But serve wrong artifact
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                            b"wrong_artifact_bytes")

        result = install_remote_package(
            remote_url="https://registry.example.com",
            package_id="test_remote_pkg",
            version="1.0.0",
            require_tls=False,
            _transport=transport,
        )
        assert result["installed"] is False
        assert result["verification_status"] == "failed"

    def test_neg_unsafe_archive_path(self, tmp_path):
        """Unsafe archive paths blocked during extraction."""
        from nodechain.sdk.remote_readiness import safe_extract, ArchiveSafetyError
        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            data = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        with pytest.raises(ArchiveSafetyError):
            safe_extract(archive, tmp_path / "dest")


# ── AC14: Full Integration Test ─────────────────────────────────────────────

class TestAC14FullIntegration:
    """AC14: Full end-to-end remote install flow."""

    def test_successful_remote_install(self, tmp_path, monkeypatch):
        """Complete remote install with all checks passing."""
        from nodechain.sdk.remote_registry import install_remote_package
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        monkeypatch.setenv("NODECHAIN_REMOTE_INSTALL_DIR", str(tmp_path / "pkgs"))

        # Set up mock registry
        transport = MockTransport()
        artifact = _make_safe_tar({
            "node.py": "print('hello')",
            "__init__.py": "",
            "package.yaml": "package_id: test_remote_pkg\nversion: 1.0.0",
        })

        reg_data = _make_registry_metadata()
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(reg_data).encode())
        pkg_data = _make_package_metadata(artifact)
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                            json.dumps(pkg_data).encode())
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                            artifact)

        result = install_remote_package(
            remote_url="https://registry.example.com",
            package_id="test_remote_pkg",
            version="1.0.0",
            require_tls=False,
            _transport=transport,
        )

        assert result["installed"] is True
        assert result["trust_level"] == "remote_untrusted"
        assert result["verification_status"] == "verified"

        # Check receipt has all fields
        receipt = result["receipt"]
        assert receipt["remote_url"] == "https://registry.example.com"
        assert receipt["registry_id"] == "test-registry-001"
        assert receipt["package_id"] == "test_remote_pkg"
        assert receipt["package_version"] == "1.0.0"
        assert receipt["artifact_digest"] != ""
        assert receipt["publisher_fingerprint"] == "pub_fp_123"
        assert receipt["receipt_digest"] != ""

        # Check install directory
        install_path = Path(result["installed_path"])
        assert (install_path / "node.py").exists()

        # Check registry entry was created
        assert result["registry_entry_id"] != ""

        # Check evidence was indexed
        assert result["evidence_indexed"]["indexed"] is True

    def test_install_receipt_is_in_evidence_chain(self, tmp_path, monkeypatch):
        """Install receipt is indexed in the evidence chain."""
        from nodechain.sdk.remote_registry import install_remote_package
        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        monkeypatch.setenv("NODECHAIN_REMOTE_INSTALL_DIR", str(tmp_path / "pkgs"))
        monkeypatch.setenv("NODECHAIN_EVIDENCE_DIR", str(tmp_path / "evidence"))

        transport = MockTransport()
        artifact = _make_safe_tar({"node.py": "pass"})
        transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                            json.dumps(_make_registry_metadata()).encode())
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                            json.dumps(_make_package_metadata(artifact)).encode())
        transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                            artifact)

        result = install_remote_package(
            remote_url="https://registry.example.com",
            package_id="test_remote_pkg",
            version="1.0.0",
            require_tls=False,
            _transport=transport,
        )
        assert result["installed"]

        # Verify evidence file exists
        receipt_id = result["receipt"]["receipt_id"]
        evidence_file = tmp_path / "evidence" / f"remote_install_{receipt_id}.json"
        assert evidence_file.exists()

        # Verify receipt content
        receipt = json.loads(evidence_file.read_text())
        assert receipt["type"] == "remote_install_receipt"
        assert receipt["trust_level"] == "remote_untrusted"
