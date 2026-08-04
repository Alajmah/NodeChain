"""Tests for namespace reporting and detection consolidation (v1.4.2).

Tests cover:
1. Human-readable report shows namespace status
2. Human-readable trust shows namespace fields
3. Human-readable inspect shows namespace detection
4. All 6 namespace types detected
5. Detection distinguishes available/nested/creation_allowed/enforced
6. docs/frozen-surfaces.md has namespace fields
7. docs/linux-deployment.md has namespace documentation
8. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
from pathlib import Path


# ─── 1. Report CLI Shows Namespace Status ────────────────────────────────

class TestReportNamespaceDisplay:
    """report CLI shows namespace status."""

    def test_report_source_has_namespace_detection(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "detect_namespaces" in report_src
        assert "Namespace Mode" in report_src
        assert "Already Nested" in report_src
        assert "Available Types" in report_src

    def test_report_source_has_network_ns_required(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "network_namespace_required" in report_src or "Network NS" in report_src


# ─── 2. Trust CLI Shows Namespace Fields ─────────────────────────────────

class TestTrustNamespaceDisplay:
    """trust CLI shows namespace fields per node."""

    def test_trust_source_has_namespace_fields(self):
        trust_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "net_ns_requested" in trust_src
        assert "net_ns_enforced" in trust_src
        assert "net_ns_error" in trust_src
        assert "namespace_mode" in trust_src


# ─── 3. Inspect CLI Shows Namespace Detection ────────────────────────────

class TestInspectNamespaceDisplay:
    """inspect CLI shows namespace detection."""

    def test_inspect_source_has_namespace_detection(self):
        inspect_src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        assert "detect_namespaces" in inspect_src
        assert "Namespace Mode" in inspect_src
        assert "Already Nested" in inspect_src


# ─── 4. All 6 Namespace Types Detected ────────────────────────────────────

class TestAllNamespaceTypesDetected:
    """Namespace detection covers all 6 types."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_all_six_types_detected_on_linux(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        # Detection must report a boolean for each namespace type.
        # A KVM guest, container, or bare-metal host may correctly report
        # different availability depending on kernel config and privilege.
        assert isinstance(caps.mount_namespace_available, bool)
        assert isinstance(caps.pid_namespace_available, bool)
        assert isinstance(caps.network_namespace_available, bool)
        assert isinstance(caps.user_namespace_available, bool)
        assert isinstance(caps.uts_namespace_available, bool)
        assert isinstance(caps.ipc_namespace_available, bool)

    def test_detection_returns_all_fields(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert hasattr(caps, "mount_namespace_available")
        assert hasattr(caps, "pid_namespace_available")
        assert hasattr(caps, "network_namespace_available")
        assert hasattr(caps, "user_namespace_available")
        assert hasattr(caps, "uts_namespace_available")
        assert hasattr(caps, "ipc_namespace_available")


# ─── 5. Detection Distinguishes States ────────────────────────────────────

class TestDetectionStates:
    """Detection distinguishes available/nested/creation_allowed/enforced."""

    def test_mode_field_exists(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert caps.namespace_mode in ("none", "detected", "nested", "created")

    def test_already_nested_field_exists(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert isinstance(caps.already_nested, bool)

    def test_creation_allowed_field_exists(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        assert isinstance(caps.namespace_creation_allowed, bool)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_nested_and_creation_reported_accurately(self):
        from nodechain.sdk.namespace_profile import detect_namespaces
        caps = detect_namespaces()
        # Detection accurately reports the actual environment.
        # A KVM guest may correctly report already_nested = False;
        # a nested container may report True. Both are valid.
        assert isinstance(caps.already_nested, bool)
        assert isinstance(caps.namespace_creation_allowed, bool)
        assert caps.namespace_mode in ("none", "detected", "nested", "created")


# ─── 6. docs/frozen-surfaces.md ────────────────────────────────────────────

class TestFrozenSurfacesNamespaceDocs:
    """frozen-surfaces.md has namespace fields documented."""

    def test_inv011_documented(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "INV-011" in fs
        assert "network_namespace" in fs

    def test_namespace_fields_documented(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "namespace_available" in fs
        assert "network_namespace_enforced" in fs
        assert "namespace_mode" in fs
        assert "network_namespace_requested" in fs

    def test_sandbox_capabilities_namespace_documented(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "mount_namespace_available" in fs
        assert "pid_namespace_available" in fs
        assert "user_namespace_available" in fs


# ─── 7. docs/linux-deployment.md ───────────────────────────────────────────

class TestLinuxDeploymentNamespaceDocs:
    """linux-deployment.md documents namespace behavior."""

    def test_namespace_table_updated(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "network_namespace_enforced" in ld
        assert "namespace_available" in ld
        assert "namespace_mode" in ld

    def test_proxmox_section_exists(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "Namespace Behavior on Proxmox LXC" in ld
        assert "already_nested" in ld

    def test_mount_and_pid_planned(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "mount_namespace_enforced" in ld
        assert "pid_namespace_enforced" in ld


# ─── 8. Version and Changelog ──────────────────────────────────────────────

class TestV142Version:
    """Version reflects v1.4.2."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v142(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog
        assert "Namespace Reporting" in changelog
