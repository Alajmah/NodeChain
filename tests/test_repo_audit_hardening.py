"""Repo Audit Hardening Tests (v2.21.3).

Tests for findings from the v2.21.3 repo audit:
    - CLI-001: trust-check _json bug fixed
    - TRUST-001/002: signature terminology clarification
    - TRUST-003: fail-closed empty trust sets
    - RUNTIME-001: loop-back cursor regression
    - DOC-001/002: documentation alignment
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _relative_metadata_dates(minutes_back: int = 5, days_forward: int = 1) -> tuple[str, str]:
    """Return (issued_at, expires_at) ISO strings relative to now.

    Avoids hardcoded dates that expire and turn the suite red on a fixed day.
    issued_at is recent (default 5 min ago) to stay inside the 24h freshness
    window the trust evaluator enforces; expires_at is in the future.
    """
    now = datetime.now(timezone.utc)
    issued = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (now + timedelta(days=days_forward)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return issued, expires

from nodechain.sdk.registry_trust import (
    SignedRegistryMetadata,
    RegistryTrustStore,
    RegistryTrustEvaluator,
    SIGNATURE_PROTOCOL_NOTE,
)
from nodechain.sdk.trust_resolver import (
    TrustAwareResolver,
)


def _pkg(package_id, version, **kwargs):
    defaults = {
        "package_id": package_id,
        "version": version,
        "artifact_digest": f"sha256:{package_id}_{version}",
        "manifest_digest": f"sha256:manifest_{package_id}_{version}",
        "publisher_fingerprint": "fp-publisher",
        "certification_digest": "",
        "lifecycle": "active",
        "sandbox_profile": "hardened_untrusted",
        "capabilities": ["read_only"],
        "dependencies": [],
    }
    defaults.update(kwargs)
    return defaults


class MockRegistry:
    def __init__(self):
        self.packages = {}

    def add(self, registry_id, package_id, version, metadata=None):
        self.packages[(registry_id, package_id, version)] = metadata or _pkg(package_id, version)

    def __call__(self, registry_id, package_id, version):
        return self.packages.get(
            (registry_id, package_id, version),
            _pkg(package_id, version),
        )
from nodechain.sdk.capability_resolver import (
    CapabilityResolutionPolicy,
)


# ── CLI-001: Trust-check uses json, not _json ──────────────────────────────

class TestCLI001TrustCheck:
    """CLI-001: Verify _json bug is fixed — json.load is used."""

    def test_json_import_not_json_alias(self):
        """The main.py should use json.load, not _json.load."""
        import inspect
        from nodechain.cli import main
        source = inspect.getsource(main)
        # The _json.load pattern should NOT exist
        assert "_json.load" not in source, "Found _json.load — CLI-001 bug present"
        # json.load should exist
        assert "json.load" in source or "import json" in source

    def test_trust_check_strict_mode_doesnt_swallow(self):
        """In strict mode, trust-check should not silently swallow exceptions."""
        import inspect
        from nodechain.cli import main
        source = inspect.getsource(main)
        # The old pattern of bare 'except Exception: pass' in trust-check
        # should be replaced with conditional strict handling
        assert "if strict:" in source, "Strict mode handling missing in trust-check"


# ── TRUST-001/002: Signature terminology ────────────────────────────────────

class TestTrustSignatureTerminology:
    """TRUST-001/002: Verify signature protocol note exists and is clear."""

    def test_signature_protocol_note_exists(self):
        assert SIGNATURE_PROTOCOL_NOTE
        assert "digest commitment" in SIGNATURE_PROTOCOL_NOTE.lower()
        assert "RSA-PSS" in SIGNATURE_PROTOCOL_NOTE or "Ed25519" in SIGNATURE_PROTOCOL_NOTE

    def test_signed_registry_metadata_has_note(self):
        """The class docstring should mention the digest commitment nature."""
        doc = SignedRegistryMetadata.__doc__ or ""
        assert "digest" in doc.lower() or "reference" in doc.lower()

    def test_metadata_verify_digest_integrity_method(self):
        """verify_digest_integrity method should exist."""
        issued_at, expires_at = _relative_metadata_dates()
        m = SignedRegistryMetadata(
            registry_id="reg-001",
            protocol_version="1",
            signer_fingerprint="fp-test",
            issued_at=issued_at,
            expires_at=expires_at,
            generation=1,
        )
        # Without metadata_digest set, verify passes (pre-v2.13 compat)
        assert m.verify_digest_integrity() is True

        # With correct digest
        m.metadata_digest = m.compute_digest()
        assert m.verify_digest_integrity() is True

        # With wrong digest
        m.metadata_digest = "wrong"
        assert m.verify_digest_integrity() is False

    def test_evaluator_rejects_tampered_digest(self, tmp_path):
        """Evaluator should reject metadata with mismatched digest."""
        # v2.67.3: use tmp_path instead of hardcoded /tmp/ — the hardcoded
        # path caused PermissionError on self-hosted CI (gha-runner non-root
        # user couldn't overwrite a file left by a prior run).
        store_path = str(tmp_path / "test_trust_store_audit.json")

        store = RegistryTrustStore(path=store_path)
        store.approve_signer("reg-001", "fp-test")

        # Create valid metadata
        issued_at, expires_at = _relative_metadata_dates()
        m = SignedRegistryMetadata(
            registry_id="reg-001",
            protocol_version="1",
            signer_fingerprint="fp-test",
            issued_at=issued_at,
            expires_at=expires_at,
            generation=1,
        )
        m.metadata_digest = m.compute_digest()

        evaluator = RegistryTrustEvaluator(trust_store=store)
        verdict = evaluator.evaluate(m)
        assert verdict.trusted  # Valid metadata

        # Tamper with digest
        m.metadata_digest = "tampered"
        verdict2 = evaluator.evaluate(m)
        assert not verdict2.trusted

    def test_reference_server_has_protocol_note(self):
        """reference_registry_server should document the signature protocol."""
        import inspect
        from nodechain.sdk import reference_registry_server
        source = inspect.getsource(reference_registry_server)
        assert "PROTOCOL NOTE" in source or "digest commitment" in source.lower()

    def test_get_signed_metadata_has_digest(self):
        """get_signed_metadata should include metadata_digest."""
        from nodechain.sdk.reference_registry_server import ReferenceRegistryServer
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            server = ReferenceRegistryServer(
                state_path=f"{tmpdir}/state.json",
                artifact_dir=tmpdir,
                registry_id="reg-001",
                registry_signer_fingerprint="fp-test",
            )
            metadata = server.get_signed_metadata()
            assert "metadata_digest" in metadata
            assert metadata["metadata_digest"] != ""
            assert "signature" in metadata  # digest commitment


# ── TRUST-003: Fail-closed empty trust sets ────────────────────────────────

class TestTrust003FailClosed:
    """TRUST-003: Empty trust sets should reject in fail-closed mode."""

    def test_fail_closed_rejects_empty_registries(self):
        """With fail_closed_empty_trust=True and no trusted registries, reject."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")
        resolver = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=True,
            trusted_registries=set(),
        )
        g = resolver.resolve("reg-001", "pkg", "1.0.0")
        assert not g.graph_admissible
        assert "fail-closed" in g.rejection_summary.lower() or "not admissible" in g.rejection_summary.lower()

    def test_fail_closed_rejects_empty_publishers(self):
        """With fail_closed_empty_trust=True and no trusted publishers, reject."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")
        resolver = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=True,
            trusted_registries={"reg-001"},
            trusted_publishers=set(),
        )
        g = resolver.resolve("reg-001", "pkg", "1.0.0")
        assert not g.graph_admissible

    def test_dev_mode_allows_empty_trust_sets(self):
        """With fail_closed_empty_trust=False (dev default), empty sets allow all."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")
        resolver = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=False,  # Dev mode
        )
        g = resolver.resolve("reg-001", "pkg", "1.0.0")
        assert g.graph_admissible

    def test_explicit_trust_works_in_fail_closed(self):
        """In fail-closed mode with explicit trust, resolution works."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")
        resolver = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=True,
            trusted_registries={"reg-001"},
            trusted_publishers={"fp-publisher"},
        )
        g = resolver.resolve("reg-001", "pkg", "1.0.0")
        assert g.graph_admissible


class TestTrust004DigestInclusion:
    """TRUST-004: fail_closed_empty_trust must be in policy digest."""

    def test_digest_changes_with_fail_closed_flag(self):
        """Two resolvers differing only in fail_closed_empty_trust must
        produce different policy digests."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")

        r_open = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=False,
        )
        r_closed = TrustAwareResolver(
            metadata_provider=reg,
            fail_closed_empty_trust=True,
        )
        assert r_open._compute_policy_digest() != r_closed._compute_policy_digest()

    def test_same_flag_produces_same_digest(self):
        """Same flag value must produce the same digest."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")

        r1 = TrustAwareResolver(metadata_provider=reg, fail_closed_empty_trust=True)
        r2 = TrustAwareResolver(metadata_provider=reg, fail_closed_empty_trust=True)
        assert r1._compute_policy_digest() == r2._compute_policy_digest()

    def test_graph_digest_reflects_flag(self):
        """The resolved graph's resolver_policy_digest must change with the flag."""
        reg = MockRegistry()
        reg.add("reg-001", "pkg", "1.0.0")

        g_open = TrustAwareResolver(
            metadata_provider=reg,
            trusted_registries={"reg-001"},
            trusted_publishers={"fp-publisher"},
            fail_closed_empty_trust=False,
        ).resolve("reg-001", "pkg", "1.0.0")

        g_closed = TrustAwareResolver(
            metadata_provider=reg,
            trusted_registries={"reg-001"},
            trusted_publishers={"fp-publisher"},
            fail_closed_empty_trust=True,
        ).resolve("reg-001", "pkg", "1.0.0")

        assert g_open.resolver_policy_digest != g_closed.resolver_policy_digest


# ── RUNTIME-001: Loop-back cursor regression ────────────────────────────────

class TestRuntime001LoopBackCursor:
    """RUNTIME-001: Verify loop-back cursor correctness with repeated node IDs."""

    def test_rebuild_order_with_loop_returns_correct_index(self):
        """When rebuilding order with a loop-back, the target node should
        be findable at the correct position for execution to resume."""
        from nodechain.runtime.scheduler import GraphScheduler
        from nodechain.core.blueprint import ChainBlueprint, NodeDef, ConnectionDef

        blueprint = ChainBlueprint(
            chain_id="test-loop",
            name="test",
            goal="test",
            nodes=[
                NodeDef(node_id="start", node_type="processor"),
                NodeDef(node_id="process", node_type="processor"),
                NodeDef(node_id="end", node_type="processor"),
            ],
            connections=[
                ConnectionDef(from_node="start", from_port="output", to_node="process", to_port="input"),
                ConnectionDef(from_node="process", from_port="output", to_node="end", to_port="input"),
            ],
        )

        scheduler = GraphScheduler(blueprint)
        order = scheduler.resolve_execution_order()
        rebuilt = scheduler.rebuild_order_with_loop(order, "process", "process")

        # The target should be findable and be the first occurrence
        idx = rebuilt.index("process")
        assert idx >= 0
        # Process should appear before end in the rebuilt order
        end_idx = rebuilt.index("end") if "end" in rebuilt else len(rebuilt)
        assert idx < end_idx

    def test_loop_target_at_correct_position(self):
        """When looping back, the target should be reachable."""
        from nodechain.runtime.scheduler import GraphScheduler
        from nodechain.core.blueprint import ChainBlueprint, NodeDef, ConnectionDef

        blueprint = ChainBlueprint(
            chain_id="test-simple-loop",
            name="test",
            goal="test",
            nodes=[
                NodeDef(node_id="a", node_type="processor"),
                NodeDef(node_id="b", node_type="processor"),
            ],
            connections=[
                ConnectionDef(from_node="a", from_port="output", to_node="b", to_port="input"),
            ],
        )

        scheduler = GraphScheduler(blueprint)
        order = scheduler.resolve_execution_order()

        # Loop back to "a" from "b"
        rebuilt = scheduler.rebuild_order_with_loop(order, "b", "a")
        # After rebuild, "a" should be findable
        idx = rebuilt.index("a")
        assert idx >= 0


# ── DOC-002: governed_install docstring ─────────────────────────────────────

class TestDoc002InstallDocstring:
    """DOC-002: Verify INSERT OR IGNORE framing removed."""

    def test_no_insert_or_ignore_in_docstring(self):
        """governed_install docstring should not reference INSERT OR IGNORE."""
        import inspect
        from nodechain.sdk import governed_install
        source = inspect.getsource(governed_install)
        assert "INSERT OR IGNORE" not in source, "DOC-002: INSERT OR IGNORE framing still present"


# ── DOC-001: README and ARCHITECTURE alignment ──────────────────────────────

class TestDoc001ReadmeArchitecture:
    """DOC-001: Verify README and ARCHITECTURE.md are updated."""

    def test_readme_mentions_remote_capabilities(self):
        """README should mention remote registry/trust capabilities."""
        readme_path = Path(__file__).parent.parent / "README.md"
        content = readme_path.read_text(encoding="utf-8")
        assert "remote" in content.lower()
        assert "registry" in content.lower()

    def test_readme_does_not_say_local_only(self):
        """README should not claim to be local-only or without registry."""
        readme_path = Path(__file__).parent.parent / "README.md"
        content = readme_path.read_text(encoding="utf-8")
        assert "local-only" not in content.lower()

    def test_architecture_marked_historical(self):
        """ARCHITECTURE.md should be marked as historical."""
        arch_path = Path(__file__).parent.parent / "ARCHITECTURE.md"
        content = arch_path.read_text(encoding="utf-8")
        assert "HISTORICAL" in content.upper() or "historical" in content.lower()
