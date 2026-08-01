"""Remote Registry Server Reference Implementation (v2.1.0).

Minimal signed HTTP server that serves protocol v1 endpoints.
The server is intentionally dumb: it serves signed metadata and artifacts.
The client verifies everything. The server is not trusted merely because
it served the bytes.

Protocol v1 endpoints:
  GET /.well-known/nodechain-registry.json
  GET /packages/{package_id}/versions/{version}.json
  GET /packages/{package_id}/versions/{version}/artifact

CLI:
  nodechain registry serve --root <dir> --host 127.0.0.1 --port <port>
  nodechain registry remote-build --root <dir> --sign <key>
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import socketserver
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_dict(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ── Registry Builder ────────────────────────────────────────────────────────


def build_registry_metadata(
    root_dir: str | Path,
    registry_id: str = "",
    registry_name: str = "NodeChain Registry",
    signer_private_key_path: str = "",
    signer_public_key_pem: str = "",
    signer_fingerprint: str = "",
) -> dict[str, Any]:
    """Build signed registry metadata from a directory of packages.

    Uses RemoteRegistryMetadata model for client-verifiable digest.
    """
    from nodechain.sdk.remote_registry import RemoteRegistryMetadata

    root = Path(root_dir)
    packages_dir = root / "packages"

    package_count = 0
    if packages_dir.exists():
        for pkg_dir in packages_dir.iterdir():
            if not pkg_dir.is_dir():
                continue
            for ver_dir in pkg_dir.iterdir():
                if ver_dir.is_dir() and (ver_dir / "metadata.json").exists():
                    package_count += 1

    # If signing, extract key info first so digest includes it
    actual_public_key = signer_public_key_pem
    actual_fingerprint = signer_fingerprint
    actual_signature = ""

    if signer_private_key_path and Path(signer_private_key_path).exists():
        from nodechain.cli.bundle_signing import _load_private_key
        import base64
        try:
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography.hazmat.primitives.asymmetric import padding as _padding
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            private_key = _load_private_key(signer_private_key_path)
            public_key = private_key.public_key()
            public_der = public_key.public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
            actual_fingerprint = hashlib.sha256(public_der).hexdigest()[:32]
            actual_public_key = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
        except ImportError:
            pass

    # Build model with all fields (including key info) BEFORE computing digest
    meta = RemoteRegistryMetadata(
        schema_version="1.0",
        registry_id=registry_id or f"reg-{uuid.uuid4().hex[:12]}",
        registry_name=registry_name,
        registry_public_key=actual_public_key,
        registry_public_key_fingerprint=actual_fingerprint,
        supported_protocol_versions=("v1",),
        packages_base_url="",
        timestamp=_now_iso(),
    )
    meta.metadata_digest = meta.compute_digest()

    # Sign the digest
    if signer_private_key_path and Path(signer_private_key_path).exists():
        try:
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography.hazmat.primitives.asymmetric import padding as _padding
            from nodechain.cli.bundle_signing import _load_private_key
            import base64 as _b64

            private_key = _load_private_key(signer_private_key_path)
            actual_signature = _b64.b64encode(private_key.sign(
                meta.metadata_digest.encode("utf-8"),
                _padding.PSS(
                    mgf=_padding.MGF1(_hashes.SHA256()),
                    salt_length=_hashes.SHA256().digest_size,
                ),
                _hashes.SHA256(),
            )).decode("ascii")
        except ImportError:
            pass

    meta.signature = actual_signature
    metadata = meta.to_dict()
    metadata["package_count"] = package_count
    if actual_signature:
        metadata["signature_algorithm"] = "RSA-PSS-SHA256"

    return metadata


def build_package_metadata(
    package_id: str,
    version: str,
    artifact_path: str | Path,
    manifest_digest: str = "",
    certification_digest: str = "",
    publisher_private_key_path: str = "",
    publisher_public_key_pem: str = "",
    publisher_fingerprint: str = "",
    capabilities: list[str] | None = None,
    sandbox_profile: str = "hardened_untrusted",
    description: str = "",
    nodes: list[str] | None = None,
) -> dict[str, Any]:
    """Build signed package metadata for an artifact."""
    from nodechain.sdk.remote_registry import RemotePackageMetadata

    artifact_path = Path(artifact_path)
    artifact_bytes = artifact_path.read_bytes()

    # Extract key info before digest computation
    actual_pub_key = publisher_public_key_pem
    actual_pub_fp = publisher_fingerprint
    actual_sig = ""

    if publisher_private_key_path and Path(publisher_private_key_path).exists():
        try:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            from nodechain.cli.bundle_signing import _load_private_key
            import hashlib as _hl

            private_key = _load_private_key(publisher_private_key_path)
            public_key = private_key.public_key()
            public_der = public_key.public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
            actual_pub_fp = _hl.sha256(public_der).hexdigest()[:32]
            actual_pub_key = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
        except ImportError:
            pass

    meta = RemotePackageMetadata(
        schema_version="1.0",
        package_id=package_id,
        version=version,
        artifact_digest=_sha256_bytes(artifact_bytes),
        artifact_size=len(artifact_bytes),
        manifest_digest=manifest_digest,
        certification_digest=certification_digest,
        publisher_public_key=actual_pub_key,
        publisher_fingerprint=actual_pub_fp,
        description=description,
        nodes=nodes or [],
        capabilities=capabilities or ["read_only"],
        sandbox_profile=sandbox_profile,
    )
    meta.metadata_digest = meta.compute_digest()

    # Sign the digest
    if publisher_private_key_path and Path(publisher_private_key_path).exists():
        try:
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography.hazmat.primitives.asymmetric import padding as _padding
            from nodechain.cli.bundle_signing import _load_private_key
            import base64 as _b64

            private_key = _load_private_key(publisher_private_key_path)
            actual_sig = _b64.b64encode(private_key.sign(
                meta.metadata_digest.encode("utf-8"),
                _padding.PSS(
                    mgf=_padding.MGF1(_hashes.SHA256()),
                    salt_length=_hashes.SHA256().digest_size,
                ),
                _hashes.SHA256(),
            )).decode("ascii")
        except ImportError:
            pass

    meta.signature = actual_sig
    metadata = meta.to_dict()
    if actual_sig:
        metadata["signature_algorithm"] = "RSA-PSS-SHA256"

    return metadata


def write_registry_to_disk(root_dir: str | Path, registry_metadata: dict[str, Any]) -> None:
    root = Path(root_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(
        json.dumps(registry_metadata, indent=2, sort_keys=True), encoding="utf-8"
    )


def write_package_metadata_to_disk(
    root_dir: str | Path, package_id: str, version: str, package_metadata: dict[str, Any]
) -> None:
    pkg_dir = Path(root_dir) / "packages" / package_id / version
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "metadata.json").write_text(
        json.dumps(package_metadata, indent=2, sort_keys=True), encoding="utf-8"
    )


# ── HTTP Server ─────────────────────────────────────────────────────────────


class RegistryRequestHandler(http.server.BaseHTTPRequestHandler):
    registry_root: str = "."
    strict: bool = True

    def log_message(self, format, *args):
        pass

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-NodeChain-Protocol", "v1")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-NodeChain-Protocol", "v1")
        self.end_headers()
        self.wfile.write(data)

    def _is_path_safe(self, path: str) -> bool:
        if ".." in path.replace("\\", "/").split("/"):
            return False
        if path.startswith("/"):
            return False
        if len(path) >= 2 and path[1] == ":":
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/.well-known/nodechain-registry.json":
            self._handle_registry_metadata()
            return

        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "packages" and parts[2] == "versions":
            self._handle_package_metadata(parts[1], parts[3].removesuffix(".json"))
            return

        if len(parts) == 5 and parts[0] == "packages" and parts[2] == "versions" and parts[4] == "artifact":
            self._handle_artifact(parts[1], parts[3])
            return

        self._send_error_json(404, f"Unknown endpoint: {path}")

    def _handle_registry_metadata(self) -> None:
        registry_file = Path(self.registry_root) / "registry.json"
        if not registry_file.exists():
            self._send_error_json(404, "Registry metadata not found")
            return
        try:
            data = json.loads(registry_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._send_error_json(500, "Invalid registry metadata")
            return
        if self.strict and not data.get("signature"):
            self._send_error_json(403, "Registry metadata is unsigned (strict mode)")
            return
        self._send_json(200, data)

    def _handle_package_metadata(self, package_id: str, version: str) -> None:
        if not self._is_path_safe(package_id) or not self._is_path_safe(version):
            self._send_error_json(400, "Invalid path")
            return
        metadata_file = Path(self.registry_root) / "packages" / package_id / version / "metadata.json"
        if not metadata_file.exists():
            self._send_error_json(404, f"Package '{package_id}' version '{version}' not found")
            return
        try:
            data = json.loads(metadata_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._send_error_json(500, f"Invalid metadata for {package_id}")
            return
        required = {"package_id", "version", "artifact_digest", "metadata_digest"}
        if not required.issubset(data.keys()):
            self._send_error_json(400, "Package metadata missing required fields")
            return
        if self.strict and not data.get("signature"):
            self._send_error_json(403, "Package metadata is unsigned (strict mode)")
            return
        self._send_json(200, data)

    def _handle_artifact(self, package_id: str, version: str) -> None:
        if not self._is_path_safe(package_id) or not self._is_path_safe(version):
            self._send_error_json(400, "Invalid path")
            return
        artifact_file = Path(self.registry_root) / "packages" / package_id / version / "artifact.tar.gz"
        if not artifact_file.exists():
            self._send_error_json(404, f"Artifact for {package_id} v{version} not found")
            return
        self._send_bytes(200, "application/gzip", artifact_file.read_bytes())

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("X-NodeChain-Protocol", "v1")
        self.end_headers()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_registry(
    root_dir: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    strict: bool = True,
    blocking: bool = True,
) -> ThreadedHTTPServer | None:
    """Start the remote registry server."""
    root = Path(root_dir).resolve()
    RegistryRequestHandler.registry_root = str(root)
    RegistryRequestHandler.strict = strict

    server = ThreadedHTTPServer((host, port), RegistryRequestHandler)

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
