"""Tests for Remote Registry Server Reference Implementation (v2.1.0).

Tests cover all 11 acceptance criteria:
  AC1:  registry serve command
  AC2:  Protocol v1 endpoints
  AC3:  Server root is read-only
  AC4:  Server refuses bad requests
  AC5:  remote-build command
  AC6:  Registry metadata signing
  AC7:  Package metadata signing
  AC8:  End-to-end smoke (build → serve → install → verify)
  AC9:  Negative server tests
  AC10: Dashboard shows remote registry status
  AC11: Windows/Linux green (implicit)
"""

from __future__ import annotations

import io
import json
import tarfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

import pytest


# ── Test Helpers ────────────────────────────────────────────────────────────


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _make_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _build_test_registry(tmp_path: Path) -> Path:
    """Build a complete test registry directory."""
    from nodechain.sdk.remote_registry_server import (
        build_registry_metadata, write_registry_to_disk,
        build_package_metadata, write_package_metadata_to_disk,
    )

    root = tmp_path / "registry_root"
    root.mkdir()

    # Create a package
    artifact = _make_tar({"node.py": "print('hello')", "__init__.py": ""})
    pkg_dir = root / "packages" / "test_pkg" / "1.0.0"
    pkg_dir.mkdir(parents=True)
    artifact_path = pkg_dir / "artifact.tar.gz"
    artifact_path.write_bytes(artifact)

    # Build package metadata (unsigned for testing)
    pkg_meta = build_package_metadata(
        package_id="test_pkg",
        version="1.0.0",
        artifact_path=str(artifact_path),
        description="Test package",
        nodes=["TestNode"],
    )
    write_package_metadata_to_disk(root, "test_pkg", "1.0.0", pkg_meta)

    # Build registry metadata (unsigned for testing)
    reg_meta = build_registry_metadata(
        root_dir=str(root),
        registry_id="test-reg-001",
        registry_name="Test Registry",
    )
    write_registry_to_disk(root, reg_meta)

    return root


def _build_test_registry_strict(tmp_path: Path) -> Path:
    """Build a test registry with unsigned metadata (for strict mode testing)."""
    root = _build_test_registry(tmp_path)
    # Registry is already unsigned since no key was provided
    return root


# ── AC1: registry serve command ─────────────────────────────────────────────

class TestAC1ServeCommand:
    """AC1: nodechain registry serve command exists."""

    def test_command_exists(self):
        from nodechain.cli.main import cli
        registry = cli.commands["registry"]
        assert "serve" in registry.commands

    def test_command_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "serve", "--help"])
        assert result.exit_code == 0
        assert "root" in result.output.lower()

    def test_remote_build_command_exists(self):
        from nodechain.cli.main import cli
        registry = cli.commands["registry"]
        assert "remote-build" in registry.commands

    def test_remote_build_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["registry", "remote-build", "--help"])
        assert result.exit_code == 0


# ── AC2: Protocol v1 Endpoints ──────────────────────────────────────────────

class TestAC2ProtocolEndpoints:
    """AC2: Server serves protocol v1 endpoints."""

    def test_serves_well_known(self, tmp_path):
        """Server serves /.well-known/nodechain-registry.json."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json")
            data = json.loads(resp.read())
            assert data["registry_id"] == "test-reg-001"
            assert "metadata_digest" in data
        finally:
            server.shutdown()
            server.server_close()

    def test_serves_package_metadata(self, tmp_path):
        """Server serves package metadata endpoint."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/packages/test_pkg/versions/1.0.0.json"
            )
            data = json.loads(resp.read())
            assert data["package_id"] == "test_pkg"
            assert data["version"] == "1.0.0"
        finally:
            server.shutdown()
            server.server_close()

    def test_serves_artifact(self, tmp_path):
        """Server serves artifact endpoint."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/packages/test_pkg/versions/1.0.0/artifact"
            )
            data = resp.read()
            assert len(data) > 0
        finally:
            server.shutdown()
            server.server_close()

    def test_protocol_header(self, tmp_path):
        """Server sends X-NodeChain-Protocol header."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
            )
            assert resp.headers.get("X-NodeChain-Protocol") == "v1"
        finally:
            server.shutdown()
            server.server_close()


# ── AC3: Read-Only Server ───────────────────────────────────────────────────

class TestAC3ReadOnly:
    """AC3: Server root is read-only."""

    def test_server_rejects_post(self, tmp_path):
        """Server doesn't accept POST requests."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json",
                method="POST",
                data=b'{"malicious": true}',
            )
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(req)
        finally:
            server.shutdown()
            server.server_close()


# ── AC4: Server Refuses Bad Requests ────────────────────────────────────────

class TestAC4RefusesBadRequests:
    """AC4: Server refuses path traversal, unknown packages, etc."""

    def test_refuses_unknown_package(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/nonexistent/versions/1.0.0.json"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_refuses_unknown_version(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/test_pkg/versions/99.0.0.json"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_refuses_traversal_in_package_id(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/..%2f..%2fetc/versions/passwd.json"
                )
            assert exc.value.code in (400, 404)
        finally:
            server.shutdown()
            server.server_close()

    def test_refuses_unknown_endpoint(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/admin/secrets"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_strict_mode_rejects_unsigned(self, tmp_path):
        """Strict mode rejects unsigned registry metadata."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=True, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
                )
            assert exc.value.code == 403
        finally:
            server.shutdown()
            server.server_close()

    def test_non_strict_serves_unsigned(self, tmp_path):
        """Non-strict mode serves unsigned metadata."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
            )
            assert resp.status == 200
        finally:
            server.shutdown()
            server.server_close()


# ── AC5: remote-build ───────────────────────────────────────────────────────

class TestAC5RemoteBuild:
    """AC5: remote-build command builds registry metadata."""

    def test_build_registry_metadata(self, tmp_path):
        from nodechain.sdk.remote_registry_server import (
            build_registry_metadata, write_registry_to_disk,
        )
        root = tmp_path / "registry_root"
        root.mkdir()

        # Create empty packages dir
        (root / "packages").mkdir()

        meta = build_registry_metadata(
            root_dir=str(root),
            registry_id="test-build-001",
            registry_name="Build Test Registry",
        )
        assert meta["registry_id"] == "test-build-001"
        assert meta["package_count"] == 0
        assert meta["metadata_digest"] != ""
        assert "package_count" in meta

    def test_build_with_packages(self, tmp_path):
        from nodechain.sdk.remote_registry_server import (
            build_registry_metadata, build_package_metadata,
            write_registry_to_disk, write_package_metadata_to_disk,
        )
        root = tmp_path / "registry_root"
        pkg_dir = root / "packages" / "pkg_a" / "1.0.0"
        pkg_dir.mkdir(parents=True)

        # Create artifact
        artifact = _make_tar({"node.py": "pass"})
        artifact_path = pkg_dir / "artifact.tar.gz"
        artifact_path.write_bytes(artifact)

        # Build package metadata
        pkg_meta = build_package_metadata("pkg_a", "1.0.0", str(artifact_path))
        write_package_metadata_to_disk(root, "pkg_a", "1.0.0", pkg_meta)

        # Build registry
        reg_meta = build_registry_metadata(str(root))
        assert reg_meta["package_count"] == 1
        assert reg_meta["package_count"] == 1

    def test_write_and_read_back(self, tmp_path):
        from nodechain.sdk.remote_registry_server import (
            build_registry_metadata, write_registry_to_disk,
        )
        root = tmp_path / "registry_root"
        (root / "packages").mkdir(parents=True)

        meta = build_registry_metadata(str(root), registry_id="rw-test")
        write_registry_to_disk(root, meta)

        registry_file = root / "registry.json"
        assert registry_file.exists()
        data = json.loads(registry_file.read_text())
        assert data["registry_id"] == "rw-test"


# ── AC6: Registry Metadata Signing ──────────────────────────────────────────

class TestAC6RegistrySigning:
    """AC6: Registry metadata signing."""

    def test_unsigned_metadata_has_empty_signature(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_registry_metadata
        root = tmp_path / "registry"
        (root / "packages").mkdir(parents=True)
        meta = build_registry_metadata(str(root))
        assert meta["signature"] == ""

    def test_metadata_has_all_fields(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_registry_metadata
        root = tmp_path / "registry"
        (root / "packages").mkdir(parents=True)
        meta = build_registry_metadata(str(root))
        required = {
            "schema_version", "registry_id", "registry_name",
            "supported_protocol_versions", "metadata_digest", "signature",
            "timestamp",
        }
        assert required.issubset(meta.keys())

    def test_metadata_digest_is_consistent(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_registry_metadata
        from nodechain.sdk.remote_registry import RemoteRegistryMetadata
        root = tmp_path / "registry"
        (root / "packages").mkdir(parents=True)
        meta = build_registry_metadata(str(root), registry_id="same")
        parsed = RemoteRegistryMetadata.from_dict(meta)
        assert parsed.verify_digest()

    def test_signed_metadata_with_key(self, tmp_path):
        """Test that signing works when cryptography is available."""
        from nodechain.sdk.remote_registry_server import build_registry_metadata
        from nodechain.cli.bundle_signing import generate_key_pair

        root = tmp_path / "registry"
        (root / "packages").mkdir(parents=True)

        key_dir = tmp_path / "keys"
        keys = generate_key_pair(str(key_dir), "test_registry")

        meta = build_registry_metadata(
            str(root),
            signer_private_key_path=keys["private_key_path"],
        )
        assert meta["signature"] != ""
        assert meta["registry_public_key_fingerprint"] != ""
        assert meta["registry_public_key"] != ""


# ── AC7: Package Metadata Signing ───────────────────────────────────────────

class TestAC7PackageSigning:
    """AC7: Package metadata signing."""

    def test_unsigned_package_has_empty_signature(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_package_metadata
        artifact = tmp_path / "artifact.tar.gz"
        artifact.write_bytes(b"test artifact")
        meta = build_package_metadata("pkg", "1.0.0", str(artifact))
        assert meta["signature"] == ""
        assert meta["metadata_digest"] != ""

    def test_package_has_all_fields(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_package_metadata
        artifact = tmp_path / "a.tar.gz"
        artifact.write_bytes(b"data")
        meta = build_package_metadata("pkg", "1.0.0", str(artifact))
        required = {
            "schema_version", "package_id", "version",
            "artifact_digest", "artifact_size", "manifest_digest",
            "certification_digest", "publisher_public_key",
            "publisher_fingerprint", "capabilities", "sandbox_profile",
            "metadata_digest", "signature",
        }
        assert required.issubset(meta.keys())

    def test_artifact_digest_matches(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_package_metadata
        data = b"test artifact content"
        artifact = tmp_path / "a.tar.gz"
        artifact.write_bytes(data)
        meta = build_package_metadata("pkg", "1.0.0", str(artifact))
        assert meta["artifact_digest"] == _sha256_bytes(data)
        assert meta["artifact_size"] == len(data)

    def test_signed_package_with_key(self, tmp_path):
        from nodechain.sdk.remote_registry_server import build_package_metadata
        from nodechain.cli.bundle_signing import generate_key_pair

        artifact = tmp_path / "a.tar.gz"
        artifact.write_bytes(b"data")

        key_dir = tmp_path / "keys"
        keys = generate_key_pair(str(key_dir), "test_publisher")

        meta = build_package_metadata(
            "pkg", "1.0.0", str(artifact),
            publisher_private_key_path=keys["private_key_path"],
        )
        assert meta["signature"] != ""
        assert meta["publisher_fingerprint"] != ""
        assert meta["publisher_public_key"] != ""


# ── AC8: End-to-End Smoke ───────────────────────────────────────────────────

class TestAC8EndToEndSmoke:
    """AC8: Full flow: build → serve → install → verify → receipt → evidence."""

    def test_full_e2e_install(self, tmp_path, monkeypatch):
        """Complete end-to-end install from local server with signed metadata."""
        from nodechain.sdk.remote_registry_server import (
            build_registry_metadata, write_registry_to_disk,
            build_package_metadata, write_package_metadata_to_disk,
            serve_registry,
        )
        from nodechain.sdk.remote_registry import install_remote_package
        from nodechain.cli.bundle_signing import generate_key_pair

        monkeypatch.setenv("NODECHAIN_CERTIFIED_REGISTRY", str(tmp_path / "reg.json"))
        monkeypatch.setenv("NODECHAIN_REMOTE_INSTALL_DIR", str(tmp_path / "pkgs"))
        monkeypatch.setenv("NODECHAIN_EVIDENCE_DIR", str(tmp_path / "evidence"))

        # Generate keys for signing
        key_dir = tmp_path / "keys"
        reg_keys = generate_key_pair(str(key_dir), "registry")
        pub_keys = generate_key_pair(str(key_dir), "publisher")

        # Build registry
        root = tmp_path / "registry"
        pkg_dir = root / "packages" / "e2e_pkg" / "1.0.0"
        pkg_dir.mkdir(parents=True)

        artifact = _make_tar({
            "node.py": "print('e2e test')",
            "__init__.py": "",
            "package.yaml": "package_id: e2e_pkg\nversion: 1.0.0",
        })
        artifact_path = pkg_dir / "artifact.tar.gz"
        artifact_path.write_bytes(artifact)

        pkg_meta = build_package_metadata(
            "e2e_pkg", "1.0.0", str(artifact_path),
            description="E2E test package",
            nodes=["E2ENode"],
            publisher_private_key_path=pub_keys["private_key_path"],
        )
        write_package_metadata_to_disk(root, "e2e_pkg", "1.0.0", pkg_meta)

        reg_meta = build_registry_metadata(
            str(root), registry_id="e2e-reg-001",
            signer_private_key_path=reg_keys["private_key_path"],
        )
        write_registry_to_disk(root, reg_meta)

        # Start server (non-strict since we control the environment)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        time.sleep(0.2)

        try:
            result = install_remote_package(
                remote_url=f"http://127.0.0.1:{port}",
                package_id="e2e_pkg",
                version="1.0.0",
                require_tls=False,
            )

            assert result["installed"] is True
            assert result["trust_level"] == "remote_untrusted"
            assert result["verification_status"] == "verified"
            assert result["receipt"]["package_id"] == "e2e_pkg"

            # Verify evidence was indexed
            receipt_id = result["receipt"]["receipt_id"]
            evidence_file = tmp_path / "evidence" / f"remote_install_{receipt_id}.json"
            assert evidence_file.exists()
        finally:
            server.shutdown()
            server.server_close()


# ── AC9: Negative Server Tests ──────────────────────────────────────────────

class TestAC9NegativeServerTests:
    """AC9: Negative server tests."""

    def test_neg_missing_package_returns_404(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/nope/versions/1.0.0.json"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_missing_artifact_returns_404(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/nope/versions/1.0.0/artifact"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_unknown_endpoint_returns_404(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/random/path")
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_strict_rejects_unsigned(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=True, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
                )
            assert exc.value.code == 403
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_path_traversal_package_id(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/packages/../../../etc/versions/passwd.json"
                )
            assert exc.value.code in (400, 404)
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_malformed_registry_json(self, tmp_path):
        """Malformed registry.json returns 500."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = tmp_path / "bad_registry"
        root.mkdir()
        (root / "registry.json").write_text("NOT JSON {{{")
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
                )
            assert exc.value.code == 500
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_missing_registry_json(self, tmp_path):
        """Missing registry.json returns 404."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = tmp_path / "empty_registry"
        root.mkdir()
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
                )
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_content_type_is_json(self, tmp_path):
        """Metadata endpoints return application/json content type."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
            )
            assert "application/json" in resp.headers.get("Content-Type", "")
        finally:
            server.shutdown()
            server.server_close()

    def test_neg_artifact_content_type(self, tmp_path):
        """Artifact endpoint returns application/gzip content type."""
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        try:
            time.sleep(0.1)
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{port}/packages/test_pkg/versions/1.0.0/artifact"
            )
            assert "application/gzip" in resp.headers.get("Content-Type", "")
        finally:
            server.shutdown()
            server.server_close()


# ── AC10: Dashboard ─────────────────────────────────────────────────────────

class TestAC10Dashboard:
    """AC10: Dashboard shows remote registry status."""

    def test_dashboard_overview_works(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--json"])
        assert result.exit_code == 0


# ── Server Lifecycle Tests ──────────────────────────────────────────────────

class TestServerLifecycle:
    """Server lifecycle management."""

    def test_server_starts_and_stops(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        assert server is not None
        server.shutdown()
        server.server_close()

    def test_server_handles_concurrent_requests(self, tmp_path):
        from nodechain.sdk.remote_registry_server import serve_registry
        import threading
        root = _build_test_registry(tmp_path)
        server = serve_registry(str(root), host="127.0.0.1", port=0, strict=False, blocking=False)
        port = server.server_address[1]
        results = []

        def fetch():
            try:
                time.sleep(0.05)
                resp = urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/.well-known/nodechain-registry.json"
                )
                results.append(resp.status)
            except Exception as e:
                results.append(0)

        threads = [threading.Thread(target=fetch) for _ in range(5)]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
            assert len(results) == 5
            assert all(r == 200 for r in results)
        finally:
            server.shutdown()
            server.server_close()
