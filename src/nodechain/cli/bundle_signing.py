"""Audit bundle signing (v1.7.0).

Cryptographic signatures for audit bundles using RSA-PSS with SHA-256.

Key management:
  nodechain audit-bundle --generate-keys --key-dir ~/.nodechain/keys

Signing:
  nodechain audit-bundle <run_id> --sign --key private.pem

Verifying:
  nodechain audit-bundle --verify bundle.zip --pubkey public.pem

Signature covers:
  - audit_bundle_schema_version
  - run_id
  - generated_at
  - file manifest (all paths, sha256, sizes)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any


def _require_cryptography():
    """Import cryptography, raise helpful error if missing."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        return rsa, padding, hashes, serialization
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for audit bundle signing. "
            "Install it with: pip install cryptography"
        )


def generate_key_pair(output_dir: str, key_name: str = "nodechain_audit") -> dict[str, str]:
    """Generate an RSA key pair for audit bundle signing.

    Args:
        output_dir: Directory to write key files.
        key_name: Base name for key files.

    Returns:
        Dict with private_key_path, public_key_path, fingerprint.
    """
    rsa, padding, hashes, serialization = _require_cryptography()

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Generate RSA 3072-bit key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    # Serialize private key (PEM, PKCS8, no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key (PEM, SubjectPublicKeyInfo)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = out / f"{key_name}_private.pem"
    public_path = out / f"{key_name}_public.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    # Compute fingerprint (SHA-256 of DER-encoded public key)
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    return {
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "fingerprint": fingerprint,
    }


def _load_private_key(key_path: str):
    """Load an RSA private key from PEM file."""
    _, _, _, serialization = _require_cryptography()
    key_data = Path(key_path).read_bytes()
    return serialization.load_pem_private_key(key_data, password=None)


def _load_public_key(key_path: str):
    """Load an RSA public key from PEM file."""
    _, _, _, serialization = _require_cryptography()
    key_data = Path(key_path).read_bytes()
    return serialization.load_pem_public_key(key_data)


def _canonicalize_signed_data(bundle_meta: dict[str, Any]) -> bytes:
    """Create canonical bytes of the data covered by the signature.

    Covers: audit_bundle_schema_version, run_id, generated_at, files manifest.
    """
    signed_fields = {
        "audit_bundle_schema_version": bundle_meta.get("audit_bundle_schema_version", ""),
        "run_id": bundle_meta.get("run_id", ""),
        "generated_at": bundle_meta.get("generated_at", ""),
        "files": bundle_meta.get("files", []),
    }
    # Canonical JSON: sorted keys, no extra whitespace
    return json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_bundle_meta(
    bundle_meta: dict[str, Any],
    private_key_path: str,
) -> dict[str, Any]:
    """Sign the bundle metadata and return enriched meta with signature.

    Args:
        bundle_meta: The bundle_meta dict (must have audit_bundle_schema_version,
                     run_id, generated_at, files).
        private_key_path: Path to PEM private key.

    Returns:
        bundle_meta with added signature fields:
          signature: base64-encoded RSA-PSS signature
          signature_algorithm: "RSA-PSS-SHA256"
          signer_key_fingerprint: SHA-256 fingerprint of signer's public key
    """
    _, padding, hashes, serialization = _require_cryptography()

    private_key = _load_private_key(private_key_path)

    # Canonical data
    signed_data = _canonicalize_signed_data(bundle_meta)

    # Sign with RSA-PSS
    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    # Compute signer fingerprint
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    enriched = dict(bundle_meta)
    enriched["signature"] = base64.b64encode(signature).decode("ascii")
    enriched["signature_algorithm"] = "RSA-PSS-SHA256"
    enriched["signature_created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    enriched["signer_key_fingerprint"] = fingerprint

    return enriched


def verify_bundle_signature(
    bundle_meta: dict[str, Any],
    public_key_path: str,
) -> dict[str, Any]:
    """Verify the signature on bundle metadata.

    Returns:
        {valid: bool, reason: str, fingerprint: str}
    """
    _, padding, hashes, serialization = _require_cryptography()

    signature_b64 = bundle_meta.get("signature", "")
    if not signature_b64:
        return {
            "valid": False,
            "reason": "No signature in bundle_meta.json",
            "fingerprint": "",
        }

    signature = base64.b64decode(signature_b64)
    algorithm = bundle_meta.get("signature_algorithm", "")

    if algorithm != "RSA-PSS-SHA256":
        return {
            "valid": False,
            "reason": f"Unsupported algorithm: {algorithm}",
            "fingerprint": bundle_meta.get("signer_key_fingerprint", ""),
        }

    public_key = _load_public_key(public_key_path)

    # Reconstruct canonical signed data
    # Note: we need to strip signature fields before canonicalizing
    meta_without_sig = dict(bundle_meta)
    del meta_without_sig["signature"]
    if "signature_algorithm" in meta_without_sig:
        del meta_without_sig["signature_algorithm"]
    if "signer_key_fingerprint" in meta_without_sig:
        del meta_without_sig["signer_key_fingerprint"]
    if "signature_created_at" in meta_without_sig:
        del meta_without_sig["signature_created_at"]

    signed_data = _canonicalize_signed_data(meta_without_sig)

    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Signature verification failed: {exc}",
            "fingerprint": bundle_meta.get("signer_key_fingerprint", ""),
        }

    return {
        "valid": True,
        "reason": "Signature valid",
        "fingerprint": bundle_meta.get("signer_key_fingerprint", ""),
    }


def compute_public_key_fingerprint(public_key_path: str) -> str:
    """Compute the SHA-256 fingerprint of a public key."""
    _, _, _, serialization = _require_cryptography()
    public_key = _load_public_key(public_key_path)
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()[:32]
