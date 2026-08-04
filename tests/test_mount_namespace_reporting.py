"""Tests for mount namespace reporting (v1.4.4).

Tests cover:
1. report CLI shows mount namespace enforcement state
2. trust CLI shows mount namespace fields per node
3. inspect CLI shows mount namespace enforcement state
4. docs/frozen-surfaces.md has mount namespace fields
5. docs/linux-deployment.md documents mount namespace prototype
6. Version and changelog
"""

from __future__ import annotations

import pytest
from pathlib import Path


# ─── 1. Report CLI ───────────────────────────────────────────────────────

class TestReportMountNS:
    """report CLI shows mount namespace enforcement state."""

    def test_report_has_mount_ns_enforced(self):
        src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "Mount NS Enforced" in src or "mount_namespace_enforced" in src


# ─── 2. Trust CLI ────────────────────────────────────────────────────────

class TestTrustMountNS:
    """trust CLI shows mount namespace fields."""

    def test_trust_has_mount_ns_fields(self):
        src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "mnt_ns_requested" in src
        assert "mnt_ns_enforced" in src
        assert "mnt_ns_error" in src


# ─── 3. Inspect CLI ──────────────────────────────────────────────────────

class TestInspectMountNS:
    """inspect CLI shows mount namespace enforcement state."""

    def test_inspect_has_mount_ns(self):
        src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        assert "Mount NS Enforced" in src or "mount_namespace_enforced" in src


# ─── 4. docs/frozen-surfaces.md ──────────────────────────────────────────

class TestFrozenSurfacesMountNS:
    """frozen-surfaces.md documents mount namespace fields."""

    def test_mount_ns_fields_in_trust_record(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "mount_namespace_requested" in fs
        assert "mount_namespace_enforced" in fs
        assert "mount_namespace_error" in fs

    def test_mount_ns_in_sandbox_capabilities(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "mount_namespace_enforced" in fs


# ─── 5. docs/linux-deployment.md ─────────────────────────────────────────

class TestLinuxDeploymentMountNS:
    """linux-deployment.md documents mount namespace prototype."""

    def test_mount_ns_in_capability_matrix(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "mount_namespace_enforced" in ld
        assert "Prototype" in ld or "v1.4.3" in ld

    def test_mount_ns_section_exists(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "Mount namespace prototype" in ld
        assert "CLONE_NEWNS" in ld
        assert "pivot_root" in ld

    def test_temp_root_noted_as_not_implemented(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "pivot_root" in ld or "read-only rootfs" in ld


# ─── 6. Version and Changelog ────────────────────────────────────────────

class TestV144Version:
    """Version reflects v1.4.4."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v144(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Mount Namespace Reporting" in changelog
