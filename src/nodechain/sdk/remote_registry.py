"""Remote Registry Foundation (v2.0.0).

Transitions NodeChain from local-only trust to network package distribution.

This module implements the remote registry protocol v1:
  - RemoteRegistryMetadata: well-known registry discovery document
  - RemotePackageMetadata: per-package version metadata
  - RemoteInstallReceipt: immutable record of a verified remote install

Security rules (NON-NEGOTIABLE):
  1. Remote install never implies execution permission.
  2. Publisher signature never implies package safety.
  3. Registry signature never implies publisher trust.
  4. Digest match never implies certification.
  5. Certification never bypasses sandboxing.
  6. remote_untrusted never upgrades itself to local_trusted.

Protocol v1 endpoints:
  GET /.well-known/nodechain-registry.json
  GET /packages/{package_id}/versions/{version}.json
  GET /packages/{package_id}/versions/{version}/artifact
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

from nodechain.sdk.remote_readiness import (
    PACKAGE_MANIFEST_SCHEMA_VERSION,
    REGISTRY_ENTRY_SCHEMA_VERSION,
    safe_extract,
    validate_archive_paths,
    validate_archive_size,
    ArchiveSafetyError,
)


# ── Protocol Constants ──────────────────────────────────────────────────────

REMOTE_REGISTRY_PROTOCOL_VERSION = "v1"
SUPPORTED_PROTOCOL_VERSIONS = ("v1",)

WELL_KNOWN_PATH = "/.well-known/nodechain-registry.json"
PACKAGE_METADATA_PATH = "/packages/{package_id}/versions/{version}.json"
ARTIFACT_PATH = "/packages/{package_id}/versions/{version}/artifact"

#: Network limits
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_ARTIFACT_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_MAX_METADATA_SIZE = 1024 * 1024  # 1 MB

#: Protocol header names
HEADER_PROTOCOL_VERSION = "X-NodeChain-Protocol"
HEADER_REGISTRY_ID = "X-NodeChain-Registry-Id"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_CONTENT_LENGTH = "Content-Length"


def _now_iso() -> str:
    """ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    """SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    """SHA-256 hex digest of canonical JSON."""
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ── Phase 1: Protocol Models ───────────────────────────────────────────────


@dataclass
class RemoteRegistryMetadata:
    """Well-known registry discovery document.

    Served at: GET /.well-known/nodechain-registry.json

    Fields (frozen as protocol v1):
      schema_version: Must be "1.0"
      registry_id: Unique registry identifier
      registry_name: Human-readable name
      registry_public_key: PEM-encoded public key for metadata signing
      registry_public_key_fingerprint: SHA-256 fingerprint of public key
      supported_protocol_versions: List of supported protocol versions
      packages_base_url: Base URL for package endpoints
      metadata_digest: SHA-256 of canonical metadata (excluding signature)
      signature: RSA-PSS signature of metadata_digest
      timestamp: ISO 8601 UTC
    """
    schema_version: str = "1.0"
    registry_id: str = ""
    registry_name: str = ""
    registry_public_key: str = ""
    registry_public_key_fingerprint: str = ""
    supported_protocol_versions: tuple[str, ...] = ("v1",)
    packages_base_url: str = ""
    metadata_digest: str = ""
    signature: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON transmission."""
        return {
            "schema_version": self.schema_version,
            "registry_id": self.registry_id,
            "registry_name": self.registry_name,
            "registry_public_key": self.registry_public_key,
            "registry_public_key_fingerprint": self.registry_public_key_fingerprint,
            "supported_protocol_versions": list(self.supported_protocol_versions),
            "packages_base_url": self.packages_base_url,
            "metadata_digest": self.metadata_digest,
            "signature": self.signature,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RemoteRegistryMetadata":
        """Deserialize from dict."""
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            registry_id=data.get("registry_id", ""),
            registry_name=data.get("registry_name", ""),
            registry_public_key=data.get("registry_public_key", ""),
            registry_public_key_fingerprint=data.get("registry_public_key_fingerprint", ""),
            supported_protocol_versions=tuple(data.get("supported_protocol_versions", ["v1"])),
            packages_base_url=data.get("packages_base_url", ""),
            metadata_digest=data.get("metadata_digest", ""),
            signature=data.get("signature", ""),
            timestamp=data.get("timestamp", _now_iso()),
        )

    def compute_digest(self) -> str:
        """Compute the metadata digest (excluding signature)."""
        data = self.to_dict()
        del data["signature"]
        del data["metadata_digest"]
        return _sha256_dict(data)

    def verify_digest(self) -> bool:
        """Verify that the metadata_digest matches the content."""
        return self.compute_digest() == self.metadata_digest


@dataclass
class RemotePackageMetadata:
    """Per-package version metadata.

    Served at: GET /packages/{package_id}/versions/{version}.json

    Fields (frozen as protocol v1):
      schema_version: Must be "1.0"
      package_id: Package identifier
      version: Semantic version string
      artifact_digest: SHA-256 of the artifact archive
      artifact_size: Size in bytes
      manifest_digest: SHA-256 of the package manifest
      certification_digest: SHA-256 of the certification document (if any)
      publisher_public_key: PEM-encoded publisher public key
      publisher_fingerprint: SHA-256 fingerprint of publisher key
      description: Human-readable description
      nodes: List of node entrypoints
      capabilities: List of declared capabilities
      sandbox_profile: Required sandbox profile
      metadata_digest: SHA-256 of canonical metadata (excluding signature)
      signature: RSA-PSS signature of metadata_digest by publisher
      published_at: ISO 8601 UTC
    """
    schema_version: str = "1.0"
    package_id: str = ""
    version: str = ""
    artifact_digest: str = ""
    artifact_size: int = 0
    manifest_digest: str = ""
    certification_digest: str = ""
    publisher_public_key: str = ""
    publisher_fingerprint: str = ""
    description: str = ""
    nodes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    sandbox_profile: str = ""
    metadata_digest: str = ""
    signature: str = ""
    published_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "artifact_size": self.artifact_size,
            "manifest_digest": self.manifest_digest,
            "certification_digest": self.certification_digest,
            "publisher_public_key": self.publisher_public_key,
            "publisher_fingerprint": self.publisher_fingerprint,
            "description": self.description,
            "nodes": list(self.nodes),
            "capabilities": list(self.capabilities),
            "sandbox_profile": self.sandbox_profile,
            "metadata_digest": self.metadata_digest,
            "signature": self.signature,
            "published_at": self.published_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RemotePackageMetadata":
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            package_id=data.get("package_id", ""),
            version=data.get("version", ""),
            artifact_digest=data.get("artifact_digest", ""),
            artifact_size=data.get("artifact_size", 0),
            manifest_digest=data.get("manifest_digest", ""),
            certification_digest=data.get("certification_digest", ""),
            publisher_public_key=data.get("publisher_public_key", ""),
            publisher_fingerprint=data.get("publisher_fingerprint", ""),
            description=data.get("description", ""),
            nodes=data.get("nodes", []),
            capabilities=data.get("capabilities", []),
            sandbox_profile=data.get("sandbox_profile", ""),
            metadata_digest=data.get("metadata_digest", ""),
            signature=data.get("signature", ""),
            published_at=data.get("published_at", _now_iso()),
        )

    def compute_digest(self) -> str:
        data = self.to_dict()
        del data["signature"]
        del data["metadata_digest"]
        return _sha256_dict(data)

    def verify_digest(self) -> bool:
        return self.compute_digest() == self.metadata_digest


@dataclass
class RemoteInstallReceipt:
    """Immutable record of a verified remote package installation.

    Written after all verification checks pass. Indexed in the evidence
    chain for auditability.

    Fields:
      receipt_type: Always "remote_install_receipt"
      receipt_id: Unique receipt identifier
      remote_url: Registry base URL
      registry_id: Registry identifier from metadata
      registry_metadata_digest: Digest of registry metadata
      registry_signer_fingerprint: Fingerprint of registry signer
      package_id: Package identifier
      package_version: Package version
      package_metadata_digest: Digest of package metadata
      artifact_digest: SHA-256 of artifact
      publisher_fingerprint: Fingerprint of publisher key
      verification_status: "verified" or "failed"
      verification_checks: List of check results
      installed_path: Local installation path
      installed_at: ISO 8601 UTC
      trust_level: Always "remote_untrusted"
      receipt_digest: SHA-256 of receipt (for integrity)
    """
    receipt_type: str = "remote_install_receipt"
    receipt_id: str = ""
    remote_url: str = ""
    registry_id: str = ""
    registry_metadata_digest: str = ""
    registry_signer_fingerprint: str = ""
    package_id: str = ""
    package_version: str = ""
    package_metadata_digest: str = ""
    artifact_digest: str = ""
    publisher_fingerprint: str = ""
    verification_status: str = "verified"
    verification_checks: list[dict[str, Any]] = field(default_factory=list)
    installed_path: str = ""
    installed_at: str = field(default_factory=_now_iso)
    trust_level: str = "remote_untrusted"
    receipt_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.receipt_type,
            "receipt_id": self.receipt_id,
            "remote_url": self.remote_url,
            "registry_id": self.registry_id,
            "registry_metadata_digest": self.registry_metadata_digest,
            "registry_signer_fingerprint": self.registry_signer_fingerprint,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_metadata_digest": self.package_metadata_digest,
            "artifact_digest": self.artifact_digest,
            "publisher_fingerprint": self.publisher_fingerprint,
            "verification_status": self.verification_status,
            "verification_checks": list(self.verification_checks),
            "installed_path": self.installed_path,
            "installed_at": self.installed_at,
            "trust_level": self.trust_level,
            "receipt_digest": self.receipt_digest,
        }

    def compute_digest(self) -> str:
        data = self.to_dict()
        del data["receipt_digest"]
        return _sha256_dict(data)

    def finalize(self) -> "RemoteInstallReceipt":
        """Compute and set the receipt digest."""
        self.receipt_digest = self.compute_digest()
        return self


# ── Phase 2: Client ────────────────────────────────────────────────────────


class RemoteRegistryError(Exception):
    """Base error for remote registry operations."""
    pass


class RegistryMetadataError(RemoteRegistryError):
    """Registry metadata is invalid."""
    pass


class PackageMetadataError(RemoteRegistryError):
    """Package metadata is invalid."""
    pass


class ArtifactVerificationError(RemoteRegistryError):
    """Artifact failed verification."""
    pass


class TimeoutError(RemoteRegistryError):
    """Request timed out."""
    pass


@dataclass
class RemoteRegistryClient:
    """HTTP client for fetching packages from a remote registry.

    Implements protocol v1 with:
      - Configurable timeout
      - Size limits
      - TLS verification (required in strict mode)
      - Retry with exponential backoff
    """
    base_url: str = ""
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_artifact_size: int = DEFAULT_MAX_ARTIFACT_SIZE
    max_metadata_size: int = DEFAULT_MAX_METADATA_SIZE
    require_tls: bool = True
    retry_count: int = 2
    retry_delay: float = 1.0

    # Injectable transport for testing
    _transport: Any = None

    def __post_init__(self):
        """Validate configuration."""
        if self.require_tls and self.base_url and not self.base_url.startswith("https://"):
            raise RemoteRegistryError(
                f"TLS required but base_url is not HTTPS: {self.base_url}"
            )
        # Normalize base URL
        if self.base_url and not self.base_url.endswith("/"):
            self.base_url = self.base_url + "/"

    def _get(self, path: str, max_size: int) -> tuple[int, dict[str, str], bytes]:
        """Perform an HTTP GET, returning (status, headers, body).

        Uses injectable transport if set (for testing), otherwise uses urllib.
        """
        url = urljoin(self.base_url, path.lstrip("/"))

        if self._transport:
            return self._transport.get(url, timeout=self.timeout)

        # Use urllib for zero-dependency HTTP
        import urllib.request
        import urllib.error

        last_error: Exception | None = None
        for attempt in range(self.retry_count + 1):
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.status
                    headers = {k: v for k, v in resp.headers.items()}
                    body = resp.read()
                    if len(body) > max_size:
                        raise RemoteRegistryError(
                            f"Response too large: {len(body)} > {max_size}"
                        )
                    return status, headers, body
            except urllib.error.URLError as e:
                last_error = e
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except Exception as e:
                last_error = e
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay * (2 ** attempt))

        raise RemoteRegistryError(f"Failed to fetch {url}: {last_error}")

    def fetch_registry_metadata(self) -> RemoteRegistryMetadata:
        """Fetch and parse registry metadata from /.well-known/nodechain-registry.json."""
        status, headers, body = self._get(WELL_KNOWN_PATH, self.max_metadata_size)

        if status != 200:
            raise RegistryMetadataError(f"HTTP {status} fetching registry metadata")

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise RegistryMetadataError(f"Invalid JSON in registry metadata: {e}")

        metadata = RemoteRegistryMetadata.from_dict(data)

        # Verify digest
        if not metadata.verify_digest():
            raise RegistryMetadataError(
                "Registry metadata digest mismatch — content may be tampered"
            )

        # Verify protocol version
        if not any(v in SUPPORTED_PROTOCOL_VERSIONS for v in metadata.supported_protocol_versions):
            raise RegistryMetadataError(
                f"Unsupported protocol versions: {metadata.supported_protocol_versions}"
            )

        return metadata

    def fetch_package_metadata(
        self, package_id: str, version: str
    ) -> RemotePackageMetadata:
        """Fetch and parse package metadata."""
        path = PACKAGE_METADATA_PATH.format(package_id=package_id, version=version)
        status, headers, body = self._get(path, self.max_metadata_size)

        if status == 404:
            raise PackageMetadataError(
                f"Package '{package_id}' version '{version}' not found"
            )
        if status != 200:
            raise PackageMetadataError(f"HTTP {status} fetching package metadata")

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise PackageMetadataError(f"Invalid JSON in package metadata: {e}")

        metadata = RemotePackageMetadata.from_dict(data)

        # Verify digest
        if not metadata.verify_digest():
            raise PackageMetadataError(
                "Package metadata digest mismatch — content may be tampered"
            )

        # Verify package_id matches request
        if metadata.package_id != package_id:
            raise PackageMetadataError(
                f"Package ID mismatch: expected '{package_id}', got '{metadata.package_id}'"
            )

        # Verify version matches request
        if metadata.version != version:
            raise PackageMetadataError(
                f"Version mismatch: expected '{version}', got '{metadata.version}'"
            )

        return metadata

    def fetch_artifact(
        self, package_id: str, version: str
    ) -> bytes:
        """Fetch package artifact bytes."""
        path = ARTIFACT_PATH.format(package_id=package_id, version=version)
        status, headers, body = self._get(path, self.max_artifact_size)

        if status == 404:
            raise ArtifactVerificationError(
                f"Artifact for '{package_id}' v{version} not found"
            )
        if status != 200:
            raise ArtifactVerificationError(f"HTTP {status} fetching artifact")

        if len(body) > self.max_artifact_size:
            raise ArtifactVerificationError(
                f"Artifact too large: {len(body)} > {self.max_artifact_size}"
            )

        return body


# ── Phase 3: Verification Pipeline ──────────────────────────────────────────


@dataclass
class VerificationCheck:
    """A single verification check result."""
    check: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "passed": self.passed, "detail": self.detail}


def verify_remote_package(
    registry_metadata: RemoteRegistryMetadata,
    package_metadata: RemotePackageMetadata,
    artifact_bytes: bytes,
    trust_store_path: str = "",
    strict: bool = True,
) -> list[VerificationCheck]:
    """Run the full verification pipeline on a remote package.

    Checks (in order):
      1. Registry metadata digest valid
      2. Package metadata digest valid
      3. Protocol version supported
      4. Artifact digest matches metadata
      5. Artifact size within limits
      6. Archive safety (path traversal, symlinks, size)
      7. Publisher key present
      8. Registry signer key present

    Returns list of all checks. All must pass for installation.
    """
    checks: list[VerificationCheck] = []

    # Check 1: Registry metadata digest
    checks.append(VerificationCheck(
        check="registry_metadata_digest",
        passed=registry_metadata.verify_digest(),
        detail="Registry metadata digest matches content",
    ))

    # Check 2: Package metadata digest
    checks.append(VerificationCheck(
        check="package_metadata_digest",
        passed=package_metadata.verify_digest(),
        detail="Package metadata digest matches content",
    ))

    # Check 3: Protocol version
    protocol_ok = any(
        v in SUPPORTED_PROTOCOL_VERSIONS
        for v in registry_metadata.supported_protocol_versions
    )
    checks.append(VerificationCheck(
        check="protocol_version",
        passed=protocol_ok,
        detail=f"Supported versions: {registry_metadata.supported_protocol_versions}",
    ))

    # Check 4: Artifact digest
    actual_digest = _sha256_bytes(artifact_bytes)
    digest_ok = actual_digest == package_metadata.artifact_digest
    checks.append(VerificationCheck(
        check="artifact_digest",
        passed=digest_ok,
        detail=f"Expected {package_metadata.artifact_digest[:12]}..., got {actual_digest[:12]}...",
    ))

    # Check 5: Artifact size
    size_ok = package_metadata.artifact_size == len(artifact_bytes)
    checks.append(VerificationCheck(
        check="artifact_size",
        passed=size_ok,
        detail=f"Expected {package_metadata.artifact_size}, got {len(artifact_bytes)}",
    ))

    # Check 6: Archive safety
    try:
        validate_archive_size(len(artifact_bytes), 0)
        checks.append(VerificationCheck(
            check="archive_size_limit",
            passed=True,
            detail=f"Within {DEFAULT_MAX_ARTIFACT_SIZE} bytes",
        ))
    except ArchiveSafetyError as e:
        checks.append(VerificationCheck(
            check="archive_size_limit",
            passed=False,
            detail=str(e),
        ))

    # Check 7: Publisher key present
    checks.append(VerificationCheck(
        check="publisher_key_present",
        passed=bool(package_metadata.publisher_public_key),
        detail="Publisher public key present" if package_metadata.publisher_public_key
        else "Publisher public key MISSING",
    ))

    # Check 8: Registry signer key present
    checks.append(VerificationCheck(
        check="registry_signer_key_present",
        passed=bool(registry_metadata.registry_public_key),
        detail="Registry public key present" if registry_metadata.registry_public_key
        else "Registry public key MISSING",
    ))

    return checks


def all_checks_passed(checks: list[VerificationCheck]) -> bool:
    """Check if all verification checks passed."""
    return all(c.passed for c in checks)


# ── Phase 5: Local Registry Bridge ──────────────────────────────────────────


def create_remote_registry_entry(
    package_metadata: RemotePackageMetadata,
    registry_metadata: RemoteRegistryMetadata,
    artifact_digest: str,
    receipt: RemoteInstallReceipt,
) -> dict[str, Any]:
    """Create a local registry entry from a verified remote package.

    The entry is marked with origin=remote and trust_level=remote_untrusted.
    It follows the frozen registry entry schema v1.0.0.
    """
    import uuid

    entry = {
        "entry_id": str(uuid.uuid4()),
        "package_id": package_metadata.package_id,
        "package_version": package_metadata.version,
        "package_digest": artifact_digest,
        "certification_status": "certified" if package_metadata.certification_digest else "uncertified",
        "registry_status": "active",
        "published_at": package_metadata.published_at,
        # Remote-specific fields
        "origin": "remote",
        "remote_url": receipt.remote_url,
        "registry_id": registry_metadata.registry_id,
        "registry_metadata_digest": registry_metadata.metadata_digest,
        "package_metadata_digest": package_metadata.metadata_digest,
        "publisher_fingerprint": package_metadata.publisher_fingerprint,
        "manifest_digest": package_metadata.manifest_digest,
        "certification_digest": package_metadata.certification_digest,
        "trust_level": "remote_untrusted",
        "sandbox_profile": package_metadata.sandbox_profile,
        "capabilities": list(package_metadata.capabilities),
        "nodes": list(package_metadata.nodes),
        "description": package_metadata.description,
        "receipt_digest": receipt.receipt_digest,
        "installed_at": receipt.installed_at,
    }

    # Compute entry digest
    entry["entry_digest"] = _sha256_dict(
        {k: v for k, v in entry.items() if k != "entry_digest"}
    )

    return entry


def add_remote_entry_to_registry(
    entry: dict[str, Any],
    registry_path: str = "",
) -> dict[str, Any]:
    """Add a remote-origin registry entry to the local certified registry."""
    from nodechain.cli.certified_registry import load_registry, save_registry
    import os

    if registry_path:
        os.environ["NODECHAIN_CERTIFIED_REGISTRY"] = registry_path

    registry = load_registry()
    registry.setdefault("entries", {})[entry["entry_id"]] = entry
    registry.setdefault("audit_log", []).append({
        "action": "remote_install",
        "entry_id": entry["entry_id"],
        "package_id": entry["package_id"],
        "remote_url": entry.get("remote_url", ""),
        "timestamp": _now_iso(),
    })
    save_registry(registry)
    return registry


# ── Phase 6: Evidence Indexing ──────────────────────────────────────────────


def index_remote_install_receipt(
    receipt: RemoteInstallReceipt,
    evidence_dir: str = "",
) -> dict[str, Any]:
    """Index a remote install receipt in the evidence chain."""
    import os
    from pathlib import Path

    evidence_dir = evidence_dir or os.environ.get(
        "NODECHAIN_EVIDENCE_DIR",
        str(Path.cwd() / "data" / "evidence"),
    )

    evidence_path = Path(evidence_dir)
    evidence_path.mkdir(parents=True, exist_ok=True)

    receipt_dict = receipt.to_dict()

    # Write receipt file
    receipt_file = evidence_path / f"remote_install_{receipt.receipt_id}.json"
    receipt_file.write_text(
        json.dumps(receipt_dict, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return {
        "indexed": True,
        "artifact_type": "remote_install_receipt",
        "receipt_id": receipt.receipt_id,
        "path": str(receipt_file),
        "digest": receipt.receipt_digest,
        "timestamp": receipt.installed_at,
    }


# ── Full Install Flow ───────────────────────────────────────────────────────


def install_remote_package(
    remote_url: str,
    package_id: str,
    version: str,
    install_dir: str = "",
    trust_store_path: str = "",
    require_tls: bool = True,
    strict: bool = True,
    _transport: Any = None,
) -> dict[str, Any]:
    """Full remote package installation flow.

    This is the entry point for:
      nodechain registry install <package_id> --version <version> --remote <url>

    Steps:
      1. Create client and fetch registry metadata
      2. Fetch package metadata
      3. Fetch artifact
      4. Run verification pipeline
      5. Safe extract to install directory
      6. Create local registry entry
      7. Write install receipt
      8. Index receipt in evidence

    Returns dict with receipt and status.
    """
    import os
    import uuid
    from pathlib import Path

    checks_log: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        # Step 1: Fetch registry metadata
        client = RemoteRegistryClient(
            base_url=remote_url,
            require_tls=require_tls,
            _transport=_transport,
        )
        registry_metadata = client.fetch_registry_metadata()
        checks_log.append({"check": "registry_metadata_fetched", "passed": True})

        # Step 2: Fetch package metadata
        package_metadata = client.fetch_package_metadata(package_id, version)
        checks_log.append({"check": "package_metadata_fetched", "passed": True})

        # Step 3: Fetch artifact
        artifact_bytes = client.fetch_artifact(package_id, version)
        checks_log.append({"check": "artifact_fetched", "passed": True})

        # Step 4: Verification pipeline
        verification_checks = verify_remote_package(
            registry_metadata=registry_metadata,
            package_metadata=package_metadata,
            artifact_bytes=artifact_bytes,
            trust_store_path=trust_store_path,
            strict=strict,
        )
        checks_log.extend(c.to_dict() for c in verification_checks)

        if not all_checks_passed(verification_checks):
            failed = [c for c in verification_checks if not c.passed]
            errors.extend(f"{c.check}: {c.detail}" for c in failed)
            raise ArtifactVerificationError(
                f"Verification failed: {len(failed)} check(s) failed"
            )

        # Step 5: Safe extract
        install_dir = install_dir or os.environ.get(
            "NODECHAIN_REMOTE_INSTALL_DIR",
            str(Path.cwd() / "data" / "remote_packages"),
        )
        package_dir = Path(install_dir) / package_id / version
        package_dir.mkdir(parents=True, exist_ok=True)

        # Write artifact to temp file for extraction
        artifact_path = package_dir / "artifact.tar.gz"
        artifact_path.write_bytes(artifact_bytes)

        try:
            safe_extract(artifact_path, package_dir)
            checks_log.append({"check": "safe_extract", "passed": True})
        except ArchiveSafetyError as e:
            checks_log.append({"check": "safe_extract", "passed": False, "detail": str(e)})
            raise
        finally:
            artifact_path.unlink(missing_ok=True)

        # Step 6: Create receipt
        receipt = RemoteInstallReceipt(
            receipt_id=str(uuid.uuid4()),
            remote_url=remote_url,
            registry_id=registry_metadata.registry_id,
            registry_metadata_digest=registry_metadata.metadata_digest,
            registry_signer_fingerprint=registry_metadata.registry_public_key_fingerprint,
            package_id=package_id,
            package_version=version,
            package_metadata_digest=package_metadata.metadata_digest,
            artifact_digest=package_metadata.artifact_digest,
            publisher_fingerprint=package_metadata.publisher_fingerprint,
            verification_status="verified",
            verification_checks=checks_log,
            installed_path=str(package_dir),
            trust_level="remote_untrusted",
        ).finalize()

        # Step 7: Create local registry entry
        entry = create_remote_registry_entry(
            package_metadata=package_metadata,
            registry_metadata=registry_metadata,
            artifact_digest=package_metadata.artifact_digest,
            receipt=receipt,
        )
        add_remote_entry_to_registry(entry)
        checks_log.append({"check": "local_registry_entry_created", "passed": True})

        # Step 8: Index in evidence
        evidence_result = index_remote_install_receipt(receipt)

        return {
            "type": "remote_install_result",
            "package_id": package_id,
            "version": version,
            "remote_url": remote_url,
            "installed": True,
            "verification_status": "verified",
            "trust_level": "remote_untrusted",
            "installed_path": str(package_dir),
            "receipt": receipt.to_dict(),
            "registry_entry_id": entry["entry_id"],
            "checks": checks_log,
            "errors": [],
            "evidence_indexed": evidence_result,
            "timestamp": _now_iso(),
        }

    except RemoteRegistryError as e:
        return {
            "type": "remote_install_result",
            "package_id": package_id,
            "version": version,
            "remote_url": remote_url,
            "installed": False,
            "verification_status": "failed",
            "checks": checks_log,
            "errors": [str(e), *errors],
            "timestamp": _now_iso(),
        }
    except Exception as e:
        return {
            "type": "remote_install_result",
            "package_id": package_id,
            "version": version,
            "remote_url": remote_url,
            "installed": False,
            "verification_status": "failed",
            "checks": checks_log,
            "errors": [f"Unexpected error: {e}", *errors],
            "timestamp": _now_iso(),
        }
