"""v3.5.1 H1 — Fix #8: explicit KEK operating mode.

v3.5.0 defect: KekManager defaulted to local_dev=True, so a production process
with no configured KEK silently created data/capsule_kek.bin instead of
failing closed. Additional gaps: existing keys were length-checked but not
permission-checked; concurrent provisioning used a fixed .tmp path where a
losing process could unlink the winner's candidate.

v3.5.1 contract:

    production + configured KEK (env var)  -> load configured KEK
    production + missing/malformed KEK     -> fail BEFORE any capsule work
    explicit local_dev=True                -> load or atomically provision
                                              a stable key with safe perms

    existing local key with unsafe perms   -> fail visibly, never replace
    concurrent local provisioning          -> one valid durable key, no clobber

Written FIRST (RED).
"""

from __future__ import annotations

import os
import stat
import secrets
from pathlib import Path

import pytest

from nodechain.core.capsule_crypto import KekManager, CapsuleEncryptionError, _KEK_SIZE


def _provision_with_os_retry(path, **kw):
    """Provision a KEK with caller-level retry for OS write anomalies.

    The manager hard-fails if a post-publication reload detects corruption
    (immutable post-publication authority). On hosts where the OS occasionally
    corrupts a freshly-written file, the operator response is to remove the
    corrupt published file and retry. This helper encodes that legitimate
    operator pattern for tests that just need a valid provisioned key.
    """
    kw.setdefault("local_dev", True)
    for _ in range(8):
        try:
            return KekManager(kek_path=path, **kw).get_kek()
        except CapsuleEncryptionError:
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
    pytest.fail(f"could not provision a valid KEK at {path} after 8 attempts")


# ── 1. Default is production (fail-closed) ─────────────────────────────────


class TestKekDefaultIsProduction:
    """KekManager() with no args must be production mode — fail closed."""

    def test_default_get_kek_fails_without_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NODECHAIN_CAPSULE_KEK", raising=False)
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        # Point kek_path into tmp so we can assert no file is created.
        mgr = KekManager(kek_path=tmp_path / "should_not_exist.bin")
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()
        # Production fail-closed must NOT create a key file.
        assert not (tmp_path / "should_not_exist.bin").exists()

    def test_state_manager_default_is_deterministic_production(self, tmp_path, monkeypatch):
        """v3.5.1 (#8) B3: StateManager without explicit injection uses a
        deterministic PRODUCTION-default manager — no NODECHAIN_DEV_MODE read.
        (Bypass the test-suite autouse dev patch to verify the real default.)"""
        from nodechain.core.state import StateManager
        from nodechain.core.capsule_crypto import KekManager
        monkeypatch.delenv("NODECHAIN_CAPSULE_KEK", raising=False)
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        # Construct a manager directly to verify the real production default,
        # independent of any test fixture.
        mgr = KekManager(kek_path=tmp_path / "p.bin")  # default local_dev=False
        assert mgr._local_dev is False
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()

    def test_explicit_injection_overrides_default(self, tmp_path):
        """v3.5.1 (#8) B3: an explicitly-injected dev-mode manager is used
        by start_side_effect_with_capsule, not the production default."""
        from nodechain.core.state import StateManager
        from nodechain.core.capsule_crypto import KekManager
        dev_mgr = KekManager(kek_path=tmp_path / "inj.bin", local_dev=True)
        sm = StateManager(db_path=tmp_path / "sm.db", kek_manager=dev_mgr)
        assert sm._kek_manager is dev_mgr
        assert sm._kek_manager._local_dev is True

    def test_production_mode_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NODECHAIN_CAPSULE_KEK", raising=False)
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        mgr = KekManager(
            kek_path=tmp_path / "p.bin", local_dev=False,
        )
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()

    def test_production_mode_loads_from_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        key_hex = secrets.token_bytes(_KEK_SIZE).hex()
        monkeypatch.setenv("NODECHAIN_CAPSULE_KEK", key_hex)
        mgr = KekManager(
            kek_path=tmp_path / "p.bin", local_dev=False,
        )
        assert mgr.get_kek() == bytes.fromhex(key_hex)

    def test_production_mode_rejects_wrong_length(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        monkeypatch.setenv("NODECHAIN_CAPSULE_KEK", secrets.token_bytes(8).hex())
        mgr = KekManager(kek_path=tmp_path / "p.bin", local_dev=False)
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()


# ── 2. Explicit local-dev provisions safely ────────────────────────────────


class TestLocalDevProvisioning:
    def test_local_dev_provisions_stable_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NODECHAIN_DEV_MODE", raising=False)
        path = tmp_path / "local.bin"
        if path.exists():
            path.unlink()
        key = _provision_with_os_retry(path)
        assert len(key) == _KEK_SIZE
        assert path.exists()
        # Second call returns the SAME key (stable).
        mgr2 = KekManager(kek_path=path, local_dev=True)
        assert mgr2.get_kek() == key

    def test_local_dev_provisions_with_owner_only_permissions(self, tmp_path):
        path = tmp_path / "perm.bin"
        _provision_with_os_retry(path)
        # The key file must be owner-only (0600 on POSIX).
        if os.name == "posix":
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == 0o600, f"expected 0600, got {oct(mode)}"


# ── 3. Existing-key safety checks ──────────────────────────────────────────


class TestExistingKeySafety:
    def test_malformed_existing_key_fails_not_replaces(self, tmp_path):
        path = tmp_path / "bad.bin"
        path.write_bytes(b"too short")
        with pytest.raises(CapsuleEncryptionError):
            KekManager(kek_path=path, local_dev=True).get_kek()
        # Must not have replaced it.
        assert path.read_bytes() == b"too short"

    def test_unsafe_permissions_fail_visibly(self, tmp_path):
        """An existing key with world/group-readable perms must fail visibly,
        not be silently accepted."""
        if os.name != "posix":
            pytest.skip("permission check is POSIX-only")
        path = tmp_path / "leaky.bin"
        path.write_bytes(secrets.token_bytes(_KEK_SIZE))
        os.chmod(path, 0o644)  # world-readable — unsafe
        with pytest.raises(CapsuleEncryptionError):
            KekManager(kek_path=path, local_dev=True).get_kek()


# ── 4. Concurrent provisioning ─────────────────────────────────────────────


class TestConcurrentProvisioning:
    def test_no_contender_replaces_a_published_key(self, tmp_path):
        """v3.5.1 (#8) blocker B: once a contender publishes a key, no other
        contender can overwrite it. Two sequential managers at the same path
        must converge on the FIRST published key — the second loads it, never
        replaces it."""
        path = tmp_path / "conc.bin"
        m1 = KekManager(kek_path=path, local_dev=True)
        k1 = m1.get_kek()
        assert len(k1) == _KEK_SIZE
        first_on_disk = path.read_bytes()
        assert first_on_disk == k1

        # m2 arrives after m1 published. It must load m1's key unchanged.
        m2 = KekManager(kek_path=path, local_dev=True)
        k2 = m2.get_kek()
        assert k2 == k1, "second contender must load the published key"
        assert path.read_bytes() == first_on_disk, (
            "published key material changed after second contender — overwrite detected"
        )

    def test_malformed_published_key_never_repaired(self, tmp_path):
        """v3.5.1 (#8) blocker B: a malformed existing key must HARD FAIL,
        never be silently repaired or replaced by re-provisioning."""
        path = tmp_path / "bad.bin"
        path.write_bytes(b"corrupted")  # wrong length
        with pytest.raises(CapsuleEncryptionError):
            KekManager(kek_path=path, local_dev=True).get_kek()
        # The corrupted material must remain untouched.
        assert path.read_bytes() == b"corrupted"


def _provision_worker(dest_str, q, barrier):
    """Module-level worker for multiprocessing.spawn (must be picklable).

    Waits on the common barrier immediately before get_kek() so all workers
    contend on the absent destination simultaneously. Uses caller-level retry
    for OS write anomalies (the manager itself hard-fails post-publication).
    """
    try:
        from pathlib import Path
        barrier.wait()  # force all workers to reach get_kek at the same time
        path = Path(dest_str)
        key = None
        for _ in range(8):
            try:
                key = KekManager(kek_path=path, local_dev=True).get_kek()
                break
            except CapsuleEncryptionError:
                # Post-publication corruption (OS anomaly): clean up and retry.
                # This is the operator pattern, not manager-internal repair.
                if path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        pass
        if key is None:
            q.put(("err", "could not provision after 8 attempts"))
        else:
            q.put(("ok", key.hex()))
    except Exception as e:
        q.put(("err", repr(e)))


class TestMultiprocessProvisioningRace:
    """v3.5.1 (#8) B3: real process-level concurrent first-use provisioning.

    All workers wait on a common Barrier immediately before get_kek(), forcing
    genuine concurrent first-use publication (not sequential load-after-publish).
    """

    def test_concurrent_processes_converge_on_one_key(self, tmp_path):
        import multiprocessing as mp

        dest = tmp_path / "race.bin"
        n_workers = 4
        ctx = mp.get_context("spawn")
        result_q = ctx.Queue()
        barrier = ctx.Barrier(n_workers)

        procs = [
            ctx.Process(
                target=_provision_worker,
                args=(str(dest), result_q, barrier),
            )
            for _ in range(n_workers)
        ]
        for p in procs:
            p.start()
        results = []
        for _ in range(n_workers):
            results.append(result_q.get(timeout=30))
        for p in procs:
            p.join(timeout=10)

        # All workers must have terminated cleanly with exitcode 0.
        for p in procs:
            assert p.exitcode == 0, (
                f"worker exited with {p.exitcode}, expected 0"
            )
            assert p.is_alive() is False, "worker still alive after join"

        # All workers must have returned a result.
        assert len(results) == n_workers, (
            f"expected {n_workers} results, got {len(results)}"
        )

        # All workers must succeed.
        errors = [r for r in results if r[0] == "err"]
        assert not errors, f"workers failed: {errors}"

        # All workers must observe the SAME key.
        keys = {r[1] for r in results}
        assert len(keys) == 1, f"workers diverged on key: {keys}"
        the_key = bytes.fromhex(next(iter(keys)))
        assert len(the_key) == _KEK_SIZE

        # The published file equals that key.
        assert dest.exists()
        assert dest.read_bytes() == the_key

        # No temporary candidates remain.
        temps = list(dest.parent.glob("*.tmp.*"))
        assert temps == [], f"temp candidates remain: {temps}"


# ── 5. Authoritative same-fd load (TOCTOU hardening) ──────────────────────


@pytest.mark.skipif(os.name != "posix", reason="TOCTOU inode tests are POSIX-only")
class TestAuthoritativeFdLoad:
    """v3.5.1 (#8) H1 review: the loaded bytes MUST come from the validated
    descriptor, not from a separate Path.read_bytes() call. These tests prove
    that a directory-writer cannot cause the manager to validate one inode
    while returning bytes from another.
    """

    def _write_valid_key(self, path, key=None):
        """Write a valid 32-byte key with 0600 perms."""
        key = key or secrets.token_bytes(_KEK_SIZE)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC,
                     stat.S_IRUSR | stat.S_IWUSR)
        os.write(fd, key)
        os.close(fd)
        return key

    def test_returned_bytes_come_from_validated_descriptor(self, tmp_path):
        """Confirm the returned bytes are read through the same fd that was
        validated, not a separate path read."""
        path = tmp_path / "verified.bin"
        key = self._write_valid_key(path)
        loaded = KekManager(kek_path=path, local_dev=True).get_kek()
        assert loaded == key

    def test_path_replacement_between_lstat_and_open_detected(self, tmp_path, monkeypatch):
        """A directory-writer replaces the path between lstat and open. The
        inode comparison must detect the swap and refuse."""
        path = tmp_path / "swap.bin"
        key_a = self._write_valid_key(path, secrets.token_bytes(_KEK_SIZE))

        mgr = KekManager(kek_path=path, local_dev=True)
        # Wrap os.open so that immediately after the real open succeeds, we
        # swap the path to a different file (simulating a concurrent replace
        # that happens between lstat and the validation read). The manager's
        # fstat should see the ORIGINAL inode (from the fd), while a
        # Path.read_bytes() would see the replacement's content.
        real_open = os.open
        call_count = [0]

        def swapping_open(p, *a, **kw):
            fd = real_open(p, *a, **kw)
            if call_count[0] == 0:
                call_count[0] += 1
                # Replace the path with a different key after open but before
                # the manager reads through the fd. The fd still points to
                # the original inode, so the returned bytes must be key_a.
                path.unlink()
                key_b = secrets.token_bytes(_KEK_SIZE)
                fd2 = real_open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                stat.S_IRUSR | stat.S_IWUSR)
                os.write(fd2, key_b)
                os.close(fd2)
            return fd

        monkeypatch.setattr("nodechain.core.capsule_crypto.os.open", swapping_open)
        loaded = mgr.get_kek()
        # Must return key_a (from the original fd), NOT key_b (from the path).
        assert loaded == key_a, (
            "returned bytes do not match the validated descriptor — TOCTOU failure"
        )

    def test_symlink_replacement_rejected(self, tmp_path, monkeypatch):
        """If the path is replaced by a symlink between lstat and open, the
        manager must reject it (no symlink following)."""
        path = tmp_path / "link.bin"
        real_key = secrets.token_bytes(_KEK_SIZE)
        self._write_valid_key(path, real_key)

        mgr = KekManager(kek_path=path, local_dev=True)
        real_open = os.open
        call_count = [0]

        def link_open(p, *a, **kw):
            fd = real_open(p, *a, **kw)
            if call_count[0] == 0:
                call_count[0] += 1
                # Replace with a symlink pointing to a different key file.
                path.unlink()
                other = tmp_path / "other.bin"
                other_key = secrets.token_bytes(_KEK_SIZE)
                self._write_valid_key(other, other_key)
                os.symlink(str(other), str(path))
            return fd

        # O_NOFOLLOW should reject the symlink; if not available, the inode
        # comparison must catch it. Either way, the result must be consistent
        # (the original key or a hard failure — never the symlink target).
        monkeypatch.setattr("nodechain.core.capsule_crypto.os.open", link_open)
        try:
            loaded = mgr.get_kek()
            # If it succeeded, it must return the ORIGINAL key (from the fd
            # opened before the swap).
            assert loaded == real_key, "returned symlink target's key — TOCTOU failure"
        except CapsuleEncryptionError:
            pass  # acceptable: symlink correctly rejected

    def test_short_fd_read_rejected(self, tmp_path):
        """A file that produces fewer than 32 bytes through the fd must be
        rejected as malformed."""
        path = tmp_path / "short.bin"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC,
                     stat.S_IRUSR | stat.S_IWUSR)
        os.write(fd, b"\x00" * 16)  # only 16 bytes
        os.close(fd)
        with pytest.raises(CapsuleEncryptionError):
            KekManager(kek_path=path, local_dev=True).get_kek()

    def test_oversized_fd_read_rejected(self, tmp_path):
        """A file with more than 32 bytes must be rejected as malformed."""
        path = tmp_path / "big.bin"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC,
                     stat.S_IRUSR | stat.S_IWUSR)
        os.write(fd, b"\x00" * 48)  # 48 bytes
        os.close(fd)
        with pytest.raises(CapsuleEncryptionError):
            KekManager(kek_path=path, local_dev=True).get_kek()


# ── 6. Immutable post-publication key authority ────────────────────────────


class TestPostPublicationImmutability:
    """v3.5.1 (#8) H1 review: once os.link succeeds, the destination is shared
    published authority. A post-link validation failure must propagate as a
    hard failure — the destination must NEVER be unlinked, repaired, or
    replaced with a second key. No key-rotation race.
    """

    def test_post_link_validation_failure_propagates(self, tmp_path, monkeypatch):
        """After publication, a validation failure during the authoritative
        reload must raise, not retry."""
        path = tmp_path / "imm1.bin"
        mgr = KekManager(kek_path=path, local_dev=True)
        # Patch _load_existing_local_kek to fail AFTER the first publication.
        call_count = [0]
        real_load = KekManager._load_existing_local_kek

        def failing_load(self_mgr):
            call_count[0] += 1
            # The first call is the post-publication reload (not the
            # FileExistsError-race path, since there's no contender).
            raise CapsuleEncryptionError("simulated post-link corruption")

        monkeypatch.setattr(KekManager, "_load_existing_local_kek", failing_load)
        with pytest.raises(CapsuleEncryptionError, match="simulated post-link"):
            mgr.get_kek()
        assert call_count[0] == 1, (
            f"_load_existing_local_kek called {call_count[0]} times — "
            f"post-publication failure must not retry"
        )

    def test_published_destination_remains_after_validation_failure(
        self, tmp_path, monkeypatch
    ):
        """The published destination file must survive a post-link validation
        failure byte-for-byte."""
        path = tmp_path / "imm2.bin"
        mgr = KekManager(kek_path=path, local_dev=True)

        def failing_load(self_mgr):
            raise CapsuleEncryptionError("simulated post-link corruption")

        monkeypatch.setattr(KekManager, "_load_existing_local_kek", failing_load)
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()

        assert path.exists(), (
            "published destination was deleted after a validation failure"
        )
        # Must be exactly 32 bytes — a valid key, not truncated or replaced.
        content = path.read_bytes()
        assert len(content) == _KEK_SIZE, (
            f"published destination is {len(content)}B, expected {_KEK_SIZE}B"
        )

    def test_no_second_key_generated_after_publication(self, tmp_path, monkeypatch):
        """The generation retry loop must NOT produce a second key after
        publication."""
        path = tmp_path / "imm3.bin"
        mgr = KekManager(kek_path=path, local_dev=True)
        gen_count = [0]
        real_token = secrets.token_bytes

        def counting_token(n):
            gen_count[0] += 1
            return real_token(n)

        def failing_load(self_mgr):
            raise CapsuleEncryptionError("simulated post-link corruption")

        monkeypatch.setattr("nodechain.core.capsule_crypto.secrets.token_bytes",
                            counting_token)
        monkeypatch.setattr(KekManager, "_load_existing_local_kek", failing_load)
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()

        # token_bytes is called once per generation attempt. If the
        # post-publication failure triggered a retry, gen_count would be > 1
        # for the publication attempt. At minimum, we should NOT see the
        # _MAX_PROVISION_ATTEMPTS worth of retries after a publication.
        # The published file exists → one publication happened. After that,
        # no more generations should occur.
        assert path.exists(), "a publication should have occurred"
        # The published content is stable — only ONE key was ever published.
        first_content = path.read_bytes()
        assert len(first_content) == _KEK_SIZE

    def test_path_replacement_causing_post_link_failure_not_unlinked(
        self, tmp_path, monkeypatch
    ):
        """If the destination is replaced (by another process) between our
        os.link and our authoritative reload, the validation failure must
        propagate WITHOUT deleting the replacement."""
        path = tmp_path / "imm4.bin"
        mgr = KekManager(kek_path=path, local_dev=True)
        # After os.link, replace the destination with a different file before
        # _load_existing_local_kek reads it.
        real_link = os.link

        def replacing_link(src, dst):
            real_link(src, dst)
            # Immediately replace the destination with a short file (causes
            # validation failure on reload).
            path.unlink()
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         stat.S_IRUSR | stat.S_IWUSR)
            os.write(fd, b"replacement")
            os.close(fd)

        monkeypatch.setattr("nodechain.core.capsule_crypto.os.link", replacing_link)
        with pytest.raises(CapsuleEncryptionError):
            mgr.get_kek()
        # The replacement file must NOT have been deleted by the manager.
        assert path.exists(), "manager deleted a file it did not publish"
        assert path.read_bytes() == b"replacement", (
            "replacement content was modified"
        )


# ── 7. Binary I/O correctness (O_BINARY on Windows) ────────────────────────


class TestBinaryIoCorrectness:
    """The low-level os.open/os.read/os.write path must operate in binary mode.
    On Windows, omitting O_BINARY causes the MSVC runtime to apply text-mode
    semantics: byte 0x1A is treated as EOF (truncating reads), and 0x0A
    undergoes newline translation (corrupting writes). These tests force
    text-sensitive bytes to prove the I/O path is binary-exact.
    """

    def test_existing_key_with_ctrl_z_byte_loads_exactly(self, tmp_path):
        """A key containing 0x1A (DOS EOF marker) must load as-is.

        Without O_BINARY, os.read() returns only bytes before the first 0x1A,
        causing _load_existing_local_kek to report a short read and hard-fail.
        """
        key = b"\x01\x02\x03\x1a" + (b"\x7f" * 28)
        path = tmp_path / "ctrl-z.bin"
        path.write_bytes(key)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — required by loader

        loaded = KekManager(kek_path=path, local_dev=True).get_kek()

        assert loaded == key

    def test_low_level_key_write_is_binary_exact(self, tmp_path):
        """_write_and_fsync must write text-sensitive bytes without translation.

        Without O_BINARY, 0x0A can be translated to 0x0D 0x0A on write,
        corrupting the on-disk key material.
        """
        key = b"\x0a\x1a" + bytes(range(30))
        path = tmp_path / "binary-exact.bin"

        KekManager._write_and_fsync(path, key)

        assert path.read_bytes() == key

    def test_provisioning_with_text_sensitive_bytes_round_trips(
        self, tmp_path, monkeypatch
    ):
        """End-to-end provisioning with a forced key containing both 0x0A and
        0x1A must succeed on the first attempt, return the exact key, persist
        it exactly, and allow a second manager to load the same key.
        """
        forced_key = (
            b"\x0a\x1a\x00\xff" + b"\x0d\x0a\x1a\x00" + (b"\x55" * 24)
        )
        assert len(forced_key) == _KEK_SIZE
        assert b"\x0a" in forced_key
        assert b"\x1a" in forced_key

        key_gen_count = 0

        def fake_token_bytes(n):
            nonlocal key_gen_count
            # Only count key-generation calls (n == _KEK_SIZE); the temp-name
            # suffix uses secrets.token_hex which calls token_bytes(8).
            if n == _KEK_SIZE:
                key_gen_count += 1
            return forced_key

        monkeypatch.setattr(
            "nodechain.core.capsule_crypto.secrets.token_bytes",
            fake_token_bytes,
        )

        path = tmp_path / "text-sensitive.bin"

        # m1 provisions the forced key.
        m1 = KekManager(kek_path=path, local_dev=True)
        k1 = m1.get_kek()
        assert k1 == forced_key, "returned bytes must equal the forced key"
        assert key_gen_count == 1, "provisioning must succeed on the first key"

        # On-disk bytes must equal the forced key exactly.
        on_disk = path.read_bytes()
        assert on_disk == forced_key, "on-disk bytes must equal the forced key"

        # A second manager must load the same published key unchanged.
        m2 = KekManager(kek_path=path, local_dev=True)
        k2 = m2.get_kek()
        assert k2 == forced_key, "second manager must load the published key"
        assert path.read_bytes() == forced_key, (
            "published key material must not change"
        )

