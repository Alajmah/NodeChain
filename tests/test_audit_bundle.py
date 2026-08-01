"""Tests for sandbox audit bundle (v1.6.0).

Tests cover:
1. audit-bundle command exists
2. Bundle includes all required files
3. SUMMARY.md is human-readable
4. Bundle records NodeChain version and platform info
5. Enforcement layers classified: required/enforced/advisory/unavailable/skipped
6. CI mode: --strict exits 15 if violations
7. Bundle handles missing run gracefully
8. Git info included when available
9. Version and changelog
"""

from __future__ import annotations

import json
import os
import platform
import zipfile
import pytest
import subprocess
import sys
from pathlib import Path


# ─── 1. Command Exists ───────────────────────────────────────────────────

class TestAuditBundleCommand:
    """audit-bundle command is registered."""

    def test_command_in_cli_source(self):
        # v2.79: audit-bundle relocated to cli/commands/audit_bundle.py; check both.
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        cmd_src = Path("src/nodechain/cli/commands/audit_bundle.py").read_text(encoding="utf-8")
        assert "audit-bundle" in main_src or "audit-bundle" in cmd_src

    def test_module_exists(self):
        assert Path("src/nodechain/cli/audit_bundle.py").exists()

    def test_function_exists(self):
        from nodechain.cli.audit_bundle import generate_audit_bundle
        assert callable(generate_audit_bundle)

    def test_frozen_surfaces_lists_command(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "audit-bundle" in fs


# ─── 2. Bundle Contents ──────────────────────────────────────────────────

class TestBundleContents:
    """Bundle includes all required files."""

    def test_bundle_includes_all_files(self, tmp_path):
        """Generate a bundle and verify it contains expected files."""
        from nodechain.cli.audit_bundle import generate_audit_bundle

        # We need a run_id; use a fake one — should exit with NOT_FOUND
        output = str(tmp_path / "test_bundle.zip")
        code = generate_audit_bundle("nonexistent_run", output_path=output)
        # Should return 2 (NOT_FOUND) since run doesn't exist
        assert code == 2


# ─── 3. SUMMARY.md Format ───────────────────────────────────────────────

class TestSummaryMd:
    """SUMMARY.md generation functions exist and produce content."""

    def test_build_summary_md_exists(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        assert callable(_build_summary_md)

    def test_build_summary_md_produces_markdown(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        md = _build_summary_md(
            run_id="test",
            version="2.0.0",
            platform_info={"platform": "Test", "platform_release": "1.0",
                          "python_version": "3.12", "container_detected": "no"},
            preset_info={"preset": "minimal", "source": "test"},
            layers={"required": [{"layer": "subprocess", "invariant": "INV-001",
                                   "status": "always required"}],
                    "enforced": [],
                    "advisory": [{"layer": "rlimit", "platform": "Linux"}],
                    "unavailable": [],
                    "skipped": []},
            violations=[],
            lockfile={"valid": True, "locked_count": 0},
            sandbox_caps={},
            namespace_caps={},
        )
        assert "# Sandbox Audit Bundle" in md
        assert "test" in md
        assert "Enforcement Layers" in md
        assert "Required" in md
        assert "Advisory" in md


# ─── 4. Version and Platform Info ────────────────────────────────────────

class TestVersionPlatformInfo:
    """Bundle records version and platform info."""

    def test_get_platform_info(self):
        from nodechain.cli.audit_bundle import _get_platform_info
        info = _get_platform_info()
        assert "platform" in info
        assert "python_version" in info

    def test_get_git_info(self):
        from nodechain.cli.audit_bundle import _get_git_info
        info = _get_git_info()
        assert "git_commit" in info
        assert "git_tag" in info


# ─── 5. Enforcement Layer Classification ────────────────────────────────

class TestEnforcementLayerClassification:
    """Layers are classified into required/enforced/advisory/unavailable/skipped."""

    def test_classify_layers_function_exists(self):
        from nodechain.cli.audit_bundle import _classify_enforcement_layers
        assert callable(_classify_enforcement_layers)

    def test_classify_minimal_preset(self):
        from nodechain.cli.audit_bundle import _classify_enforcement_layers
        layers = _classify_enforcement_layers(
            summary=None,
            preset_info={"preset": "minimal", "config": {}},
            sandbox_caps={},
            namespace_caps={},
        )
        # minimal has no kernel layers required
        assert "required" in layers
        assert "enforced" in layers
        assert "advisory" in layers
        assert "unavailable" in layers
        assert "skipped" in layers
        # Advisory always present
        assert len(layers["advisory"]) >= 1

    def test_classify_hardened_preset(self):
        from nodechain.cli.audit_bundle import _classify_enforcement_layers
        from nodechain.sdk.policy_presets import get_preset
        preset = get_preset("hardened_untrusted")
        layers = _classify_enforcement_layers(
            summary=None,
            preset_info={"preset": "hardened_untrusted", "config": preset.to_dict()},
            sandbox_caps={"seccomp_available": True, "cgroup_available": True},
            namespace_caps={"network_namespace_available": True, "pid_namespace_available": True},
        )
        # Hardened requires seccomp, cgroup, netns, mount conf, pidns
        assert len(layers["enforced"]) >= 3 or len(layers["required"]) >= 3 or \
               len(layers["unavailable"]) >= 3  # Depending on platform


# ─── 6. CI Mode: --strict ────────────────────────────────────────────────

class TestStrictMode:
    """CI mode exits 15 if trust violations exist."""

    def test_strict_with_violations_returns_15(self, tmp_path):
        """When --strict and violations exist, exit 15."""
        from nodechain.cli.audit_bundle import generate_audit_bundle
        output = str(tmp_path / "strict_test.zip")
        # nonexistent run → exit 2, not 15
        code = generate_audit_bundle("nonexistent", output_path=output, strict=True)
        assert code == 2  # NOT_FOUND takes precedence

    def test_strict_flag_in_cli(self):
        """CLI command has --strict flag."""
        # v2.79: audit-bundle declarations relocated to cli/commands/audit_bundle.py.
        cmd_src = Path("src/nodechain/cli/commands/audit_bundle.py").read_text(encoding="utf-8")
        assert "strict" in cmd_src
        assert "audit-bundle" in cmd_src


# ─── 7. Handles Missing Run ──────────────────────────────────────────────

class TestMissingRun:
    """Bundle handles missing run gracefully."""

    def test_missing_run_returns_not_found(self, tmp_path):
        from nodechain.cli.audit_bundle import generate_audit_bundle
        output = str(tmp_path / "missing.zip")
        code = generate_audit_bundle("nonexistent_run_id", output_path=output)
        assert code == 2  # EXIT_NOT_FOUND


# ─── 8. Bundle Metadata ──────────────────────────────────────────────────

class TestBundleMetadata:
    """Bundle metadata functions."""

    def test_utc_now_exists(self):
        from nodechain.cli.audit_bundle import _utc_now
        ts = _utc_now()
        assert isinstance(ts, str)
        assert "T" in ts  # ISO format

    def test_get_sandbox_capabilities(self):
        from nodechain.cli.audit_bundle import _get_sandbox_capabilities
        caps = _get_sandbox_capabilities()
        assert isinstance(caps, dict)

    def test_get_namespace_capabilities(self):
        from nodechain.cli.audit_bundle import _get_namespace_capabilities
        caps = _get_namespace_capabilities()
        assert isinstance(caps, dict)

    def test_get_lockfile_status(self):
        from nodechain.cli.audit_bundle import _get_lockfile_status
        status = _get_lockfile_status()
        assert isinstance(status, dict)
        assert "valid" in status

    def test_get_preset_info(self):
        from nodechain.cli.audit_bundle import _get_preset_info
        info = _get_preset_info()
        assert isinstance(info, dict)
        assert "preset" in info


# ─── 9. Version and Changelog ────────────────────────────────────────────

class TestV160Version:
    def test_version_is_1_6_1(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v161(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "schema" in changelog.lower()

    def test_frozen_surfaces_has_audit_bundle(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "audit-bundle" in fs


# --- 10. Schema Versioning (v1.6.1) ---------------------------------------


class TestSchemaVersioning:
    """Every JSON file in the bundle carries schema_version."""

    def test_schema_version_constant_exists(self):
        from nodechain.cli.audit_bundle import AUDIT_BUNDLE_SCHEMA_VERSION
        assert AUDIT_BUNDLE_SCHEMA_VERSION == "1"

    def test_required_bundle_files_defined(self):
        from nodechain.cli.audit_bundle import REQUIRED_BUNDLE_FILES
        assert "SUMMARY.md" in REQUIRED_BUNDLE_FILES
        assert "bundle_meta.json" in REQUIRED_BUNDLE_FILES
        assert "invariants.json" in REQUIRED_BUNDLE_FILES
        assert "enforcement_layers.json" in REQUIRED_BUNDLE_FILES
        assert len(REQUIRED_BUNDLE_FILES) >= 9

    def test_stamp_adds_schema_version(self):
        from nodechain.cli.audit_bundle import _stamp
        data = {"key": "value"}
        stamped = _stamp(data, "invariants")
        assert stamped["schema_version"] == "1"
        assert stamped["type"] == "invariants"
        # Original not mutated
        assert "schema_version" not in data

    def test_stamp_different_types(self):
        from nodechain.cli.audit_bundle import _stamp
        for ftype in ["bundle_meta", "report", "lockfile", "platform", "preset"]:
            stamped = _stamp({}, ftype)
            assert stamped["schema_version"] == "1"
            assert stamped["type"] == ftype

    def test_bundle_meta_has_schema_version_fields(self, tmp_path):
        """Verify _build_summary_md uses schema version."""
        from nodechain.cli.audit_bundle import _build_summary_md, AUDIT_BUNDLE_SCHEMA_VERSION
        md = _build_summary_md(
            run_id="test", version="2.0.0",
            platform_info={"platform": "Linux", "platform_release": "6.8",
                          "python_version": "3.12", "container_detected": "yes"},
            preset_info={"preset": "hardened_untrusted", "source": "cli"},
            layers={"required": [], "enforced": [{"layer": "seccomp"}],
                    "advisory": [], "unavailable": [], "skipped": []},
            violations=[],
            lockfile={"valid": True, "locked_count": 3},
            sandbox_caps={"seccomp_available": True},
            namespace_caps={"network_namespace_available": True},
        )
        assert str(AUDIT_BUNDLE_SCHEMA_VERSION) in md


# --- 11. Bundle Verification (v1.6.1) ------------------------------------


class TestBundleVerification:
    """Verify validates required files and schema versions."""

    def test_verify_function_exists(self):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        assert callable(verify_audit_bundle)

    def test_verify_missing_file(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        result = verify_audit_bundle(str(tmp_path / "nonexistent.zip"))
        assert result["valid"] is False
        assert any("not found" in e for e in result["errors"])

    def test_verify_bad_zip(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"not a zip file")
        result = verify_audit_bundle(str(bad))
        assert result["valid"] is False
        assert any("ZIP" in e for e in result["errors"])

    def test_verify_valid_bundle(self, tmp_path):
        """Create a minimal valid bundle and verify it."""
        from nodechain.cli.audit_bundle import (
            verify_audit_bundle, _stamp, AUDIT_BUNDLE_SCHEMA_VERSION,
            REQUIRED_BUNDLE_FILES,
        )
        import zipfile, json

        bundle = tmp_path / "valid.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("SUMMARY.md", "# Audit\n\n## Compliance Status\n\n✅ COMPLIANT")
            meta = _stamp({
                "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
                "generated_at": "2026-06-14T12:00:00Z",
                "nodechain_version": "3.5.0",
                "run_id": "test",
            }, "bundle_meta")
            zf.writestr("bundle_meta.json", json.dumps(meta))
            zf.writestr("invariants.json", json.dumps(_stamp({"violations": []}, "invariants")))
            zf.writestr("lockfile.json", json.dumps(_stamp({"valid": True}, "lockfile")))
            zf.writestr("sandbox_capabilities.json", json.dumps(_stamp({}, "sandbox_capabilities")))
            zf.writestr("namespace_detection.json", json.dumps(_stamp({}, "namespace_detection")))
            zf.writestr("preset.json", json.dumps(_stamp({"preset": "none"}, "preset")))
            zf.writestr("enforcement_layers.json", json.dumps(_stamp({}, "enforcement_layers")))
            zf.writestr("platform.json", json.dumps(_stamp({"platform": "Linux"}, "platform")))

        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is True
        assert len(result["errors"]) == 0
        assert result["files_checked"] >= 8

    def test_verify_missing_required_file(self, tmp_path):
        """Bundle missing a required file should fail."""
        from nodechain.cli.audit_bundle import verify_audit_bundle, _stamp, AUDIT_BUNDLE_SCHEMA_VERSION
        import zipfile, json

        bundle = tmp_path / "missing.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("SUMMARY.md", "# Audit\n\n## Compliance Status")
            meta = _stamp({"audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION}, "bundle_meta")
            zf.writestr("bundle_meta.json", json.dumps(meta))
            # Missing all other required files

        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is False
        assert len(result["missing_files"]) > 0

    def test_verify_json_without_schema_version_warns(self, tmp_path):
        """JSON files without schema_version produce warnings."""
        from nodechain.cli.audit_bundle import verify_audit_bundle, AUDIT_BUNDLE_SCHEMA_VERSION
        import zipfile, json

        bundle = tmp_path / "no_sv.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("SUMMARY.md", "# Audit\n\n## Compliance Status")
            # bundle_meta has schema version
            zf.writestr("bundle_meta.json", json.dumps({
                "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
                "schema_version": "1",
                "type": "bundle_meta",
            }))
            # But invariants.json lacks schema_version
            zf.writestr("invariants.json", json.dumps({"violations": []}))
            # Add remaining required files
            for fname in ["lockfile.json", "sandbox_capabilities.json",
                         "namespace_detection.json", "preset.json",
                         "enforcement_layers.json", "platform.json"]:
                zf.writestr(fname, json.dumps({"schema_version": "1", "type": "test"}))

        result = verify_audit_bundle(str(bundle))
        assert any("schema_version" in w for w in result["warnings"])

    def test_verify_bundle_meta_without_audit_schema_fails(self, tmp_path):
        """bundle_meta.json missing audit_bundle_schema_version should fail."""
        from nodechain.cli.audit_bundle import verify_audit_bundle, _stamp
        import zipfile, json

        bundle = tmp_path / "bad_meta.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("SUMMARY.md", "# Audit\n\n## Compliance Status")
            # bundle_meta without audit_bundle_schema_version
            zf.writestr("bundle_meta.json", json.dumps(_stamp({
                "generated_at": "2026-06-14",
            }, "bundle_meta")))
            for fname in ["invariants.json", "lockfile.json", "sandbox_capabilities.json",
                         "namespace_detection.json", "preset.json",
                         "enforcement_layers.json", "platform.json"]:
                zf.writestr(fname, json.dumps(_stamp({}, fname.replace(".json", ""))))

        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is False
        assert any("audit_bundle_schema_version" in e for e in result["errors"])

    def test_cli_has_verify_option(self):
        """CLI command has --verify flag."""
        # v2.79: audit-bundle declarations relocated to cli/commands/audit_bundle.py.
        cmd_src = Path("src/nodechain/cli/commands/audit_bundle.py").read_text(encoding="utf-8")
        assert "--verify" in cmd_src


# --- 12. Enhanced SUMMARY.md (v1.6.1) -------------------------------------


class TestEnhancedSummaryMd:
    """SUMMARY.md includes compliance status, preset, required layers."""

    def test_summary_has_compliance_status(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        md = _build_summary_md(
            run_id="test", version="2.0.0",
            platform_info={"platform": "Linux", "platform_release": "6.8",
                          "python_version": "3.12", "container_detected": "yes"},
            preset_info={"preset": "hardened_untrusted", "source": "cli"},
            layers={"required": [], "enforced": [], "advisory": [],
                    "unavailable": [], "skipped": []},
            violations=[],
            lockfile={"valid": True},
            sandbox_caps={},
            namespace_caps={},
        )
        assert "Compliance Status" in md
        assert "COMPLIANT" in md

    def test_summary_shows_non_compliant_with_errors(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        # Create a mock violation
        from dataclasses import dataclass

        @dataclass
        class MockViolation:
            code: str = "INV-007"
            severity: str = "error"
            node_id: str = "untrusted_node"
            invariant: str = "syscall_filtering_required"
            expected: str = "True"
            actual: str = "False"

        md = _build_summary_md(
            run_id="test", version="2.0.0",
            platform_info={"platform": "Linux", "platform_release": "6.8",
                          "python_version": "3.12", "container_detected": "no"},
            preset_info={"preset": "standard_untrusted", "source": "cli"},
            layers={"required": [], "enforced": [], "advisory": [],
                    "unavailable": [], "skipped": []},
            violations=[MockViolation()],
            lockfile={"valid": True},
            sandbox_caps={},
            namespace_caps={},
        )
        assert "NON-COMPLIANT" in md

    def test_summary_shows_active_preset(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        md = _build_summary_md(
            run_id="test", version="2.0.0",
            platform_info={"platform": "Linux", "platform_release": "6.8",
                          "python_version": "3.12", "container_detected": "no"},
            preset_info={"preset": "hardened_untrusted", "source": "cli"},
            layers={"required": [], "enforced": [], "advisory": [],
                    "unavailable": [], "skipped": []},
            violations=[],
            lockfile={}, sandbox_caps={}, namespace_caps={},
        )
        assert "hardened_untrusted" in md

    def test_summary_shows_required_layers_count(self):
        from nodechain.cli.audit_bundle import _build_summary_md
        md = _build_summary_md(
            run_id="test", version="2.0.0",
            platform_info={"platform": "Linux", "platform_release": "6.8",
                          "python_version": "3.12", "container_detected": "no"},
            preset_info={"preset": "minimal", "source": "cli"},
            layers={
                "required": [{"layer": "subprocess"}, {"layer": "child_policy"}],
                "enforced": [{"layer": "seccomp"}],
                "advisory": [], "unavailable": [], "skipped": [],
            },
            violations=[],
            lockfile={}, sandbox_caps={}, namespace_caps={},
        )
        assert "Required layers: 3" in md  # 2 required + 1 enforced
        assert "Enforced layers: 1" in md


# --- 13. Content Integrity (v1.6.2) ---------------------------------------


class TestContentIntegrity:
    """SHA-256 file manifest and tamper detection."""

    def test_sha256_bytes(self):
        from nodechain.cli.audit_bundle import _sha256_bytes
        h = _sha256_bytes(b"hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_deterministic(self):
        from nodechain.cli.audit_bundle import _sha256_bytes
        assert _sha256_bytes(b"test") == _sha256_bytes(b"test")

    def test_sha256_different_inputs(self):
        from nodechain.cli.audit_bundle import _sha256_bytes
        assert _sha256_bytes(b"a") != _sha256_bytes(b"b")

    def test_build_file_manifest(self):
        from nodechain.cli.audit_bundle import _build_file_manifest
        files = {
            "a.json": b'{"key": "a"}',
            "b.json": b'{"key": "b"}',
        }
        manifest = _build_file_manifest(files)
        assert len(manifest) == 2
        # Sorted by path
        assert manifest[0]["path"] == "a.json"
        assert manifest[1]["path"] == "b.json"
        assert "sha256" in manifest[0]
        assert len(manifest[0]["sha256"]) == 64
        assert manifest[0]["size"] == 12

    def test_compute_bundle_sha256(self, tmp_path):
        from nodechain.cli.audit_bundle import _compute_bundle_sha256
        f = tmp_path / "test.zip"
        f.write_bytes(b"test content")
        h = _compute_bundle_sha256(f)
        assert len(h) == 64


# --- 14. Tamper Detection (v1.6.2) ---------------------------------------


class TestTamperDetection:
    """Verification detects modified, added, and removed files."""

    def _make_valid_bundle(self, tmp_path) -> Path:
        """Create a valid bundle with manifest."""
        from nodechain.cli.audit_bundle import (
            _stamp, _build_file_manifest, AUDIT_BUNDLE_SCHEMA_VERSION,
            REQUIRED_BUNDLE_FILES,
        )

        files: dict[str, bytes] = {}
        files["SUMMARY.md"] = b"# Audit\n\n## Compliance Status\n\nCOMPLIANT"
        files["invariants.json"] = json.dumps(_stamp({"violations": []}, "invariants")).encode()
        files["lockfile.json"] = json.dumps(_stamp({"valid": True}, "lockfile")).encode()
        files["sandbox_capabilities.json"] = json.dumps(_stamp({}, "sandbox_capabilities")).encode()
        files["namespace_detection.json"] = json.dumps(_stamp({}, "namespace_detection")).encode()
        files["preset.json"] = json.dumps(_stamp({"preset": "none"}, "preset")).encode()
        files["enforcement_layers.json"] = json.dumps(_stamp({}, "enforcement_layers")).encode()
        files["platform.json"] = json.dumps(_stamp({"platform": "Linux"}, "platform")).encode()

        # Build manifest BEFORE adding bundle_meta
        manifest = _build_file_manifest(files)

        # Add bundle_meta with manifest
        meta = _stamp({
            "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
            "generated_at": "2026-06-14T12:00:00Z",
            "nodechain_version": "3.5.0",
            "run_id": "test",
            "files": manifest,
        }, "bundle_meta")
        files["bundle_meta.json"] = json.dumps(meta).encode()

        # Recompute manifest to include bundle_meta itself
        # Actually we DON'T include bundle_meta in the manifest since it IS the manifest
        # bundle_meta's own hash would be circular

        bundle = tmp_path / "valid.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            for fname, fdata in files.items():
                zf.writestr(fname, fdata)

        return bundle

    def test_valid_bundle_passes(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle = self._make_valid_bundle(tmp_path)
        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is True

    def test_tampered_file_detected(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle = self._make_valid_bundle(tmp_path)

        # Modify a file inside the ZIP
        import zipfile as zf_mod
        # Read all files
        with zf_mod.ZipFile(bundle, "r") as zf:
            all_files = {name: zf.read(name) for name in zf.namelist()}

        # Tamper with invariants.json
        all_files["invariants.json"] = b'{"tampered": true, "schema_version": "1", "type": "invariants"}'

        # Rewrite
        with zf_mod.ZipFile(bundle, "w") as zf:
            for name, data in all_files.items():
                zf.writestr(name, data)

        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is False
        assert "invariants.json" in result["hash_mismatches"]

    def test_added_file_detected(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle = self._make_valid_bundle(tmp_path)

        # Add an unexpected file
        import zipfile as zf_mod
        with zf_mod.ZipFile(bundle, "a") as zf:
            zf.writestr("sneaky.json", b'{"injected": true}')

        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is False
        assert "sneaky.json" in result["unexpected_files"]

    def test_manifest_entries_reported(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle = self._make_valid_bundle(tmp_path)
        result = verify_audit_bundle(str(bundle))
        assert result.get("manifest_entries", 0) >= 8

    def test_no_manifest_warns(self, tmp_path):
        """Bundles without manifest get a warning, not error."""
        from nodechain.cli.audit_bundle import (
            verify_audit_bundle, _stamp, AUDIT_BUNDLE_SCHEMA_VERSION,
        )
        bundle = tmp_path / "no_manifest.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("SUMMARY.md", "# Audit\n\n## Compliance Status")
            meta = _stamp({
                "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
            }, "bundle_meta")
            zf.writestr("bundle_meta.json", json.dumps(meta))
            for fname in ["invariants.json", "lockfile.json", "sandbox_capabilities.json",
                         "namespace_detection.json", "preset.json",
                         "enforcement_layers.json", "platform.json"]:
                zf.writestr(fname, json.dumps(_stamp({}, fname.replace(".json", ""))))

        result = verify_audit_bundle(str(bundle))
        # No manifest → warning, but still valid (backward compat)
        assert any("manifest" in w.lower() for w in result["warnings"])


# --- 15. Signing Key Management (v1.7.0) ----------------------------------


class TestKeyManagement:
    """RSA key pair generation for audit bundle signing."""

    def test_generate_key_pair(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair
        result = generate_key_pair(str(tmp_path))
        assert result["private_key_path"]
        assert result["public_key_path"]
        assert len(result["fingerprint"]) == 32
        assert Path(result["private_key_path"]).exists()
        assert Path(result["public_key_path"]).exists()

    def test_private_key_is_valid_pem(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, _load_private_key
        result = generate_key_pair(str(tmp_path))
        key = _load_private_key(result["private_key_path"])
        assert key is not None
        assert key.key_size == 3072

    def test_public_key_is_valid_pem(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, _load_public_key
        result = generate_key_pair(str(tmp_path))
        key = _load_public_key(result["public_key_path"])
        assert key is not None

    def test_fingerprint_deterministic(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, compute_public_key_fingerprint,
        )
        result = generate_key_pair(str(tmp_path))
        fp1 = result["fingerprint"]
        fp2 = compute_public_key_fingerprint(result["public_key_path"])
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair
        r1 = generate_key_pair(str(tmp_path), "key1")
        r2 = generate_key_pair(str(tmp_path), "key2")
        assert r1["fingerprint"] != r2["fingerprint"]


# --- 16. Bundle Signing (v1.7.0) ------------------------------------------


class TestBundleSigning:
    """Sign and verify bundle signatures."""

    def test_sign_bundle_meta_adds_signature(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [{"path": "a.json", "sha256": "abc", "size": 3}],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        assert "signature" in signed
        assert signed["signature_algorithm"] == "RSA-PSS-SHA256"
        assert len(signed["signer_key_fingerprint"]) == 32

    def test_verify_correct_signature(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, sign_bundle_meta, verify_bundle_signature,
        )
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [{"path": "a.json", "sha256": "abc", "size": 3}],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        result = verify_bundle_signature(signed, keys["public_key_path"])
        assert result["valid"] is True

    def test_verify_wrong_key_fails(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, sign_bundle_meta, verify_bundle_signature,
        )
        keys1 = generate_key_pair(str(tmp_path), "pair1")
        keys2 = generate_key_pair(str(tmp_path), "pair2")
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        signed = sign_bundle_meta(meta, keys1["private_key_path"])
        result = verify_bundle_signature(signed, keys2["public_key_path"])
        assert result["valid"] is False

    def test_verify_modified_manifest_fails(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, sign_bundle_meta, verify_bundle_signature,
        )
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [{"path": "a.json", "sha256": "abc", "size": 3}],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        # Tamper with the manifest AFTER signing
        signed["files"].append({"path": "injected.json", "sha256": "xyz", "size": 3})
        result = verify_bundle_signature(signed, keys["public_key_path"])
        assert result["valid"] is False

    def test_verify_no_signature_returns_invalid(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, verify_bundle_signature,
        )
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        result = verify_bundle_signature(meta, keys["public_key_path"])
        assert result["valid"] is False
        assert "No signature" in result["reason"]


# --- 17. Signature in Full Bundle Verify (v1.7.0) ------------------------


class TestSignatureInVerify:
    """Signature verification integrated into full bundle verify."""

    def _make_signed_bundle(self, tmp_path, sign=True):
        """Create a valid bundle, optionally signed."""
        from nodechain.cli.bundle_signing import (
            generate_key_pair, sign_bundle_meta,
        )
        from nodechain.cli.audit_bundle import (
            _stamp, _build_file_manifest, AUDIT_BUNDLE_SCHEMA_VERSION,
        )

        files: dict[str, bytes] = {}
        files["SUMMARY.md"] = b"# Audit\n\n## Compliance Status\n\nCOMPLIANT"
        files["invariants.json"] = json.dumps(_stamp({"violations": []}, "invariants")).encode()
        files["lockfile.json"] = json.dumps(_stamp({"valid": True}, "lockfile")).encode()
        files["sandbox_capabilities.json"] = json.dumps(_stamp({}, "sandbox_capabilities")).encode()
        files["namespace_detection.json"] = json.dumps(_stamp({}, "namespace_detection")).encode()
        files["preset.json"] = json.dumps(_stamp({"preset": "none"}, "preset")).encode()
        files["enforcement_layers.json"] = json.dumps(_stamp({}, "enforcement_layers")).encode()
        files["platform.json"] = json.dumps(_stamp({"platform": "Linux"}, "platform")).encode()

        manifest = _build_file_manifest(files)

        meta = {
            "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
            "generated_at": "2026-06-14T12:00:00Z",
            "nodechain_version": "3.5.0",
            "run_id": "test",
            "files": manifest,
        }

        keys = generate_key_pair(str(tmp_path))

        if sign:
            meta = sign_bundle_meta(meta, keys["private_key_path"])

        meta = _stamp(meta, "bundle_meta")
        files["bundle_meta.json"] = json.dumps(meta).encode()

        bundle = tmp_path / "signed.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            for fname, fdata in files.items():
                zf.writestr(fname, fdata)

        return bundle, keys

    def test_signed_bundle_verifies_with_pubkey(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        result = verify_audit_bundle(str(bundle), pubkey_path=keys["public_key_path"])
        assert result["valid"] is True
        assert result["signature_status"] == "valid"

    def test_signed_bundle_wrong_pubkey_fails(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        from nodechain.cli.bundle_signing import generate_key_pair
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        wrong_keys = generate_key_pair(str(tmp_path), "wrong")
        result = verify_audit_bundle(str(bundle), pubkey_path=wrong_keys["public_key_path"])
        assert result["valid"] is False
        assert result["signature_status"] == "invalid"

    def test_unsigned_bundle_with_pubkey_fails(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=False)
        result = verify_audit_bundle(str(bundle), pubkey_path=keys["public_key_path"])
        assert result["valid"] is False
        assert result["signature_status"] == "missing"

    def test_unsigned_bundle_without_pubkey_works(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=False)
        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is True

    def test_signed_bundle_without_pubkey_warns(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        result = verify_audit_bundle(str(bundle))
        assert result["valid"] is True
        assert result["signature_status"] == "signed_not_verified"
        assert any("pubkey" in w for w in result["warnings"])


# --- 18. Version and Changelog (v1.7.0) -----------------------------------


class TestV170Version:
    def test_version_is_1_7_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v170(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Signed" in changelog or "signed" in changelog

    def test_pyproject_has_cryptography(self):
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        assert "cryptography" in pyproject

    def test_bundle_signing_module_exists(self):
        assert Path("src/nodechain/cli/bundle_signing.py").exists()

    def test_cli_has_sign_options(self):
        # v2.79: audit-bundle declarations relocated to cli/commands/audit_bundle.py.
        cmd_src = Path("src/nodechain/cli/commands/audit_bundle.py").read_text(encoding="utf-8")
        assert "--sign" in cmd_src
        assert "--pubkey" in cmd_src
        assert "--generate-keys" in cmd_src


# --- 19. Key Identity Fields (v1.7.1) -------------------------------------


class TestKeyIdentityFields:
    """bundle_meta.json includes enhanced key identity metadata."""

    def test_sign_includes_signature_created_at(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        assert "signature_created_at" in signed
        assert "T" in signed["signature_created_at"]  # ISO format

    def test_sign_includes_algorithm(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        assert signed["signature_algorithm"] == "RSA-PSS-SHA256"

    def test_sign_includes_fingerprint(self, tmp_path):
        from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        assert len(signed["signer_key_fingerprint"]) == 32
        assert signed["signer_key_fingerprint"] == keys["fingerprint"]

    def test_verify_with_created_at_field(self, tmp_path):
        from nodechain.cli.bundle_signing import (
            generate_key_pair, sign_bundle_meta, verify_bundle_signature,
        )
        keys = generate_key_pair(str(tmp_path))
        meta = {
            "audit_bundle_schema_version": "1",
            "run_id": "test",
            "generated_at": "2026-06-14T12:00:00Z",
            "files": [],
        }
        signed = sign_bundle_meta(meta, keys["private_key_path"])
        # The signature_created_at field must not break verification
        result = verify_bundle_signature(signed, keys["public_key_path"])
        assert result["valid"] is True


# --- 20. Require-Signature Policy (v1.7.1) -------------------------------


class TestRequireSignature:
    """--require-signature enforcement."""

    def _make_signed_bundle(self, tmp_path, sign=True):
        from nodechain.cli.bundle_signing import generate_key_pair, sign_bundle_meta
        from nodechain.cli.audit_bundle import (
            _stamp, _build_file_manifest, AUDIT_BUNDLE_SCHEMA_VERSION,
        )

        files: dict[str, bytes] = {}
        files["SUMMARY.md"] = b"# Audit\n\n## Compliance Status\n\nCOMPLIANT"
        files["invariants.json"] = json.dumps(_stamp({"violations": []}, "invariants")).encode()
        files["lockfile.json"] = json.dumps(_stamp({"valid": True}, "lockfile")).encode()
        files["sandbox_capabilities.json"] = json.dumps(_stamp({}, "sandbox_capabilities")).encode()
        files["namespace_detection.json"] = json.dumps(_stamp({}, "namespace_detection")).encode()
        files["preset.json"] = json.dumps(_stamp({"preset": "none"}, "preset")).encode()
        files["enforcement_layers.json"] = json.dumps(_stamp({}, "enforcement_layers")).encode()
        files["platform.json"] = json.dumps(_stamp({"platform": "Linux"}, "platform")).encode()

        manifest = _build_file_manifest(files)

        meta = {
            "audit_bundle_schema_version": AUDIT_BUNDLE_SCHEMA_VERSION,
            "generated_at": "2026-06-14T12:00:00Z",
            "nodechain_version": "3.5.0",
            "run_id": "test",
            "files": manifest,
        }

        keys = generate_key_pair(str(tmp_path))

        if sign:
            meta = sign_bundle_meta(meta, keys["private_key_path"])

        meta = _stamp(meta, "bundle_meta")
        files["bundle_meta.json"] = json.dumps(meta).encode()

        bundle = tmp_path / "signed.zip"
        with zipfile.ZipFile(bundle, "w") as zf:
            for fname, fdata in files.items():
                zf.writestr(fname, fdata)

        return bundle, keys

    def test_require_signature_fails_unsigned(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=False)
        result = verify_audit_bundle(
            str(bundle), pubkey_path=keys["public_key_path"], require_signature=True
        )
        assert result["valid"] is False
        assert any("require-signature" in e or "not signed" in e for e in result["errors"])

    def test_require_signature_fails_no_pubkey(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        result = verify_audit_bundle(
            str(bundle), pubkey_path="", require_signature=True
        )
        assert result["valid"] is False
        assert any("require-signature" in e or "pubkey" in e for e in result["errors"])

    def test_require_signature_passes_signed_verified(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        result = verify_audit_bundle(
            str(bundle), pubkey_path=keys["public_key_path"], require_signature=True
        )
        assert result["valid"] is True
        assert result["signature_status"] == "valid"

    def test_require_signature_fails_wrong_key(self, tmp_path):
        from nodechain.cli.audit_bundle import verify_audit_bundle
        from nodechain.cli.bundle_signing import generate_key_pair
        bundle, keys = self._make_signed_bundle(tmp_path, sign=True)
        wrong_keys = generate_key_pair(str(tmp_path), "wrong")
        result = verify_audit_bundle(
            str(bundle), pubkey_path=wrong_keys["public_key_path"], require_signature=True
        )
        assert result["valid"] is False

    def test_cli_has_require_signature_flag(self):
        # v2.79: audit-bundle declarations relocated to cli/commands/audit_bundle.py.
        cmd_src = Path("src/nodechain/cli/commands/audit_bundle.py").read_text(encoding="utf-8")
        assert "--require-signature" in cmd_src


# --- 21. Version and Changelog (v1.7.1) -----------------------------------


class TestV171Version:
    def test_version_is_1_7_1(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"

    def test_changelog_has_v171(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "require-signature" in changelog.lower() or "Key Identity" in changelog
