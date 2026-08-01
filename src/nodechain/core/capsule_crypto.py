"""v3.5.0: Capsule encryption and per-run key hierarchy.

Key hierarchy (INV-004, DEC-001):
    Master Key (KEK) — supplied through configured secret or auto-generated
        for local development. Persisted to a stable filesystem location
        (NOT in SQLite). Owner-only permissions (0600).
    Per-Run DEK — random 256-bit key, generated once per run, encrypted
        under the KEK with AES-256-GCM, persisted in run_encryption_keys.
    Capsule Payload — encrypted under the per-run DEK with AES-256-GCM.

AES-256-GCM with 96-bit nonce. Authenticated additional data binds capsule
identity to its context (domain-separated, versioned).

ChatGPT guardrail #1: KEK is generated once and durably stored, not per
construction. Production fails closed when KEK is absent. Only explicit
local-development mode auto-provisions one.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CapsuleEncryptionError(Exception):
    """Raised when capsule encryption/decryption or key management fails."""


# Domain-separated prefix for AES-GCM additional authenticated data.
_AAD_PREFIX = b"nodechain:side-effect-replay-capsule:v1"

# Nonce size for AES-GCM (96 bits = 12 bytes, the standard for GCM).
_NONCE_SIZE = 12

# KEK size (256 bits = 32 bytes).
_KEK_SIZE = 32

# DEK size (256 bits = 32 bytes).
_DEK_SIZE = 32


def _build_aad(
    run_id: str,
    capsule_id: str,
    side_effect_key: str,
    capsule_schema_version: int,
    canonicalization_version: str,
) -> bytes:
    """Build versioned, domain-separated authenticated additional data.

    ChatGPT guardrail #6: use a canonical encoding, not simple concatenation.
    """
    parts = [
        _AAD_PREFIX,
        run_id.encode("utf-8"),
        capsule_id.encode("utf-8"),
        side_effect_key.encode("utf-8"),
        str(capsule_schema_version).encode("utf-8"),
        canonicalization_version.encode("utf-8"),
    ]
    return b"\x00".join(parts)


def generate_dek() -> bytes:
    """Generate a random 256-bit DEK."""
    return secrets.token_bytes(_DEK_SIZE)


def wrap_dek(kek: bytes, dek: bytes) -> tuple[bytes, bytes]:
    """Encrypt (wrap) a DEK under the KEK using AES-256-GCM.

    Returns (ciphertext, nonce).
    """
    nonce = secrets.token_bytes(_NONCE_SIZE)
    aesgcm = AESGCM(kek)
    # AAD for key wrapping binds the purpose.
    aad = b"nodechain:run-dek-wrap:v1"
    ciphertext = aesgcm.encrypt(nonce, dek, aad)
    return ciphertext, nonce


def unwrap_dek(kek: bytes, wrapped_dek: bytes, nonce: bytes) -> bytes:
    """Decrypt (unwrap) a DEK using the KEK.

    Raises CapsuleEncryptionError on authentication failure.
    """
    aesgcm = AESGCM(kek)
    aad = b"nodechain:run-dek-wrap:v1"
    try:
        return aesgcm.decrypt(nonce, wrapped_dek, aad)
    except Exception as exc:
        raise CapsuleEncryptionError(
            f"Failed to unwrap DEK (wrong KEK or corrupted data): {exc}"
        ) from exc


def encrypt_capsule_payload(
    dek: bytes,
    plaintext: bytes,
    run_id: str,
    capsule_id: str,
    side_effect_key: str,
    capsule_schema_version: int,
    canonicalization_version: str,
) -> tuple[bytes, bytes]:
    """Encrypt capsule plaintext under the DEK using AES-256-GCM.

    Returns (ciphertext, nonce).
    """
    nonce = secrets.token_bytes(_NONCE_SIZE)
    aesgcm = AESGCM(dek)
    aad = _build_aad(
        run_id, capsule_id, side_effect_key,
        capsule_schema_version, canonicalization_version,
    )
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def decrypt_capsule_payload(
    dek: bytes,
    ciphertext: bytes,
    nonce: bytes,
    run_id: str,
    capsule_id: str,
    side_effect_key: str,
    capsule_schema_version: int,
    canonicalization_version: str,
) -> bytes:
    """Decrypt capsule ciphertext under the DEK.

    Raises CapsuleEncryptionError on authentication failure (wrong key,
    modified ciphertext, or modified AAD).
    """
    aesgcm = AESGCM(dek)
    aad = _build_aad(
        run_id, capsule_id, side_effect_key,
        capsule_schema_version, canonicalization_version,
    )
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CapsuleEncryptionError(
            f"Failed to decrypt capsule (wrong DEK, modified ciphertext, "
            f"or modified AAD): {exc}"
        ) from exc


class KekManager:
    """Manages the master key (KEK) for capsule encryption.

    ChatGPT guardrail #1: the KEK is generated once and durably stored.
    Production fails closed when the configured KEK is absent. Only explicit
    local-development mode auto-provisions one.

    ChatGPT guardrail #7:
        - ordinary run with no governed side effect: no KEK required
        - governed side effect in local-dev mode: stable KEK generated or loaded
        - governed side effect in production mode with missing KEK: fail before started
        - malformed or permission-unsafe local key: fail visibly; do not replace
    """

    def __init__(
        self,
        *,
        kek_path: str | Path | None = None,
        kek_env_var: str = "NODECHAIN_CAPSULE_KEK",
        local_dev: bool = False,
    ) -> None:
        """Initialize the KEK manager.

        v3.5.1 (#8): the default is PRODUCTION (local_dev=False), which fails
        closed when the configured KEK is absent. Local auto-provisioning must
        be deliberately selected by the composition root (e.g. test fixtures
        or an explicit local-dev entrypoint) by constructing KekManager with
        ``local_dev=True``. The mode is resolved ONLY from this constructor
        argument — there is no environment-variable fallback inside get_kek,
        so persistence and recovery code never silently re-derives the mode.

        Args:
            kek_path: filesystem path for local-dev KEK storage. Defaults to
                data/capsule_kek.bin relative to CWD.
            kek_env_var: environment variable for production KEK (hex-encoded).
            local_dev: if True, auto-provision a KEK for local development.
                If False (production default), require the env var.
        """
        self._kek_path = Path(kek_path) if kek_path else Path("data/capsule_kek.bin")
        self._kek_env_var = kek_env_var
        self._local_dev = local_dev
        self._kek: bytes | None = None

    def get_kek(self) -> bytes:
        """Return the KEK, loading or provisioning it as needed.

        v3.5.1 (#8): the operating mode is resolved SOLELY from the
        ``local_dev`` constructor argument — no environment-variable
        coupling inside this method. The composition root (CLI/runtime)
        constructs the KekManager with the mode it already resolved and
        injects it; persistence/recovery code consumes the injected manager.

        Production: load from env var; fail closed if absent.
        Local-dev: load from file, or generate-once-and-store if absent.
        """
        if self._kek is not None:
            return self._kek

        if self._local_dev:
            self._kek = self._load_or_provision_local_kek()
        else:
            self._kek = self._load_production_kek()

        return self._kek

    def _load_production_kek(self) -> bytes:
        """Load KEK from environment variable. Fail closed if absent."""
        import os
        hex_key = os.environ.get(self._kek_env_var)
        if not hex_key:
            raise CapsuleEncryptionError(
                f"Production mode requires {self._kek_env_var} to be set "
                f"(hex-encoded 256-bit key). Local-development mode must be "
                f"explicitly selected by the composition root."
            )
        try:
            key = bytes.fromhex(hex_key)
        except ValueError as exc:
            raise CapsuleEncryptionError(
                f"{self._kek_env_var} is not valid hex: {exc}"
            ) from exc
        if len(key) != _KEK_SIZE:
            raise CapsuleEncryptionError(
                f"{self._kek_env_var} must be {_KEK_SIZE} bytes "
                f"({_KEK_SIZE * 2} hex chars), got {len(key)}"
            )
        return key

    def _load_or_provision_local_kek(self) -> bytes:
        """Load KEK from file, or generate once and persist for local-dev.

        v3.5.1 (#8) algorithmic contract (reviewer blocker B):
        - write in a loop until exactly 32 bytes are written;
        - use a unique temporary path;
        - flush and fsync before publication;
        - verify temporary-file length and content before publication;
        - publish WITHOUT overwriting an existing destination (hard link with
          O_CREAT|O_EXCL); on race-loss, discard the local candidate and load
          the winner;
        - once the destination exists, malformed content or unsafe permissions
          cause a HARD failure — never repair or replacement.
        """
        # Existing destination: load-or-hard-fail. Never repair or replace.
        if self._kek_path.exists():
            return self._load_existing_local_kek()

        # Provision a new key into a unique temp file.
        self._kek_path.parent.mkdir(parents=True, exist_ok=True)
        # Bounded retry on the GENERATION path only — defensive pre-publication
        # verification. If a fresh-key write fails to round-trip (historically
        # attributed to Windows text-mode byte translation before O_BINARY was
        # added; now guarded by O_BINARY), we re-roll the key and rewrite. This
        # is safe because no destination exists yet and each attempt uses a
        # unique temp name. The LOAD path above does NOT retry — a malformed
        # existing key is a hard failure.
        _MAX_PROVISION_ATTEMPTS = 8
        for _attempt in range(_MAX_PROVISION_ATTEMPTS):
            key = secrets.token_bytes(_KEK_SIZE)
            tmp_path = self._kek_path.with_suffix(
                f".tmp.{os.getpid()}.{secrets.token_hex(8)}"
            )
            # A stale temp from a crashed prior attempt is uniquely ours;
            # remove it before exclusive creation.
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            try:
                self._write_and_fsync(tmp_path, key)
                # Pre-publish verification of the temp file.
                written = tmp_path.read_bytes()
                if written != key:
                    # Transient write corruption on a FRESH key: re-roll.
                    # No destination file was created.
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                    continue
                # Publish WITHOUT overwriting: os.link creates a hard link and
                # fails with FileExistsError if the destination already exists.
                # This is the atomic no-overwrite primitive.
                try:
                    os.link(str(tmp_path), str(self._kek_path))
                except FileExistsError:
                    # Another contender won the race. Discard our candidate
                    # and load the winner (never overwritten). A corrupt
                    # winner is a hard failure (never repair existing material).
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                    return self._load_existing_local_kek()
                # Published successfully. v3.5.1 (#8) H1 review: once os.link
                # succeeds, the destination is SHARED PUBLISHED AUTHORITY —
                # another process may have already loaded it. The
                # authoritative reload via _load_existing_local_kek either
                # returns the published key or HARD-FAILS. We must NEVER
                # catch, unlink, or retry after publication. Doing so would
                # create a key-rotation race (K1 loaded by one process, K2
                # published by another). Any CapsuleEncryptionError from the
                # reload propagates while the destination is preserved.
                return self._load_existing_local_kek()
            except OSError:
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                raise
            finally:
                # Always clean up our temp, whether we won or lost.
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
        else:
            raise CapsuleEncryptionError(
                f"Failed to provision a valid KEK at {self._kek_path} after "
                f"{_MAX_PROVISION_ATTEMPTS} attempts — every write round-trip "
                f"verification failed. No destination file was created. "
                f"Check the host filesystem."
            )

    def _load_existing_local_kek(self) -> bytes:
        """Load an existing local KEK through ONE descriptor.

        v3.5.1 (#8) H1 review: the entire operation — type check, inode
        verification, permission/ownership validation, AND byte read — happens
        through a single file descriptor. This eliminates the TOCTOU window
        where a directory-writer could swap the path between validating one
        inode and reading bytes from another.

        Algorithm:
        1. lstat(path) → reject symlink / non-regular
        2. open(path, O_RDONLY | O_NOFOLLOW where available)
        3. fstat(fd) → verify (st_dev, st_ino) match lstat (detect swap)
        4. verify regular file, owner UID, 0600 (POSIX)
        5. read through fd in a loop; require exactly 32 bytes then EOF
        6. return those bytes

        Never repairs or replaces malformed material.
        """
        path = self._kek_path

        # 1. lstat to reject symlinks/non-regular before opening.
        try:
            lst = os.lstat(path)
        except OSError as e:
            raise CapsuleEncryptionError(
                f"Local KEK at {path}: lstat failed: {e}. Refusing to use it."
            ) from e
        if not stat.S_ISREG(lst.st_mode):
            raise CapsuleEncryptionError(
                f"Local KEK at {path} is not a regular file "
                f"(mode {oct(stat.S_IMODE(lst.st_mode))}). Refusing to use it."
            )

        # 2. open with O_NOFOLLOW where available (rejects symlinks at the
        #    kernel level). Fall back to plain O_RDONLY on platforms without it.
        #    O_BINARY is required on Windows: without it the MSVC runtime opens
        #    in text mode, where byte 0x1A is treated as EOF and 0x0A undergoes
        #    newline translation — corrupting cryptographic key material.
        open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if no_follow:
            open_flags |= no_follow
        try:
            fd = os.open(path, open_flags)
        except OSError as e:
            raise CapsuleEncryptionError(
                f"Local KEK at {path}: open failed: {e}. Refusing to use it."
            ) from e

        try:
            # 3. fstat the descriptor and verify it identifies the SAME inode
            #    as the lstat above. This detects a path swap between lstat
            #    and open.
            try:
                fst = os.fstat(fd)
            except OSError as e:
                raise CapsuleEncryptionError(
                    f"Local KEK at {path}: fstat failed: {e}. Refusing to use it."
                ) from e
            if fst.st_dev != lst.st_dev or fst.st_ino != lst.st_ino:
                raise CapsuleEncryptionError(
                    f"Local KEK at {path}: inode changed between lstat and open "
                    f"(possible TOCTOU race). Refusing to use it."
                )

            # 4. Validate regular file, owner, and permissions through the fd.
            if not stat.S_ISREG(fst.st_mode):
                raise CapsuleEncryptionError(
                    f"Local KEK at {path}: fd is not a regular file."
                )
            if os.name == "posix":
                mode = stat.S_IMODE(fst.st_mode)
                if mode & 0o077:
                    raise CapsuleEncryptionError(
                        f"Local KEK at {path} has unsafe permissions "
                        f"({oct(mode)}); expected 0600 (owner-only). "
                        f"Refusing to use it — fix permissions or remove the key."
                    )
                if fst.st_uid != os.geteuid():
                    raise CapsuleEncryptionError(
                        f"Local KEK at {path} is not owned by the current "
                        f"process (uid {fst.st_uid} != euid {os.geteuid()}). "
                        f"Refusing to use it."
                    )

            # 5. Read the key through the validated descriptor in a loop.
            #    Require exactly _KEK_SIZE bytes followed by EOF — reject
            #    short and oversized reads.
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > _KEK_SIZE:
                    raise CapsuleEncryptionError(
                        f"Local KEK at {path} is malformed "
                        f"(expected {_KEK_SIZE} bytes, got >{total}). "
                        f"Refusing to replace it — fix or remove manually."
                    )
                chunks.append(chunk)
            if total != _KEK_SIZE:
                raise CapsuleEncryptionError(
                    f"Local KEK at {path} is malformed "
                    f"(expected {_KEK_SIZE} bytes, got {total}). "
                    f"Refusing to replace it — fix or remove manually."
                )
            return b"".join(chunks)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    @staticmethod
    def _write_and_fsync(path: Path, data: bytes) -> None:
        """Write ``data`` to ``path`` in a loop until all bytes are flushed,
        then fsync the file. Raises on write failure."""
        fd = os.open(
            str(path),
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_TRUNC
            | getattr(os, "O_BINARY", 0),
            stat.S_IRUSR | stat.S_IWUSR,  # 0600
        )
        try:
            # Write loop: os.write may write fewer bytes than requested.
            offset = 0
            while offset < len(data):
                n = os.write(fd, data[offset:])
                if n <= 0:
                    raise OSError("os.write returned non-positive byte count")
                offset += n
            os.fsync(fd)
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise


def resolve_kek_manager_from_environment() -> "KekManager":
    """v3.5.1 (#8) B3: composition-root helper for CLI/API entrypoints.

    Resolves the KEK operating mode from ``NODECHAIN_DEV_MODE`` ONCE at the
    composition boundary and returns a fully-constructed KekManager. This is
    the ONLY place outside tests that reads the dev-mode flag. The returned
    manager is injected into StateManager; KekManager.get_kek and the
    persistence layer never read the environment.
    """
    import os
    local_dev = os.environ.get("NODECHAIN_DEV_MODE", "0") == "1"
    return KekManager(local_dev=local_dev)
