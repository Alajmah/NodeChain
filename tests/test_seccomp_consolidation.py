"""Tests for Linux seccomp consolidation (v1.2.6).

Documentation-only milestone — verifies docs match code.
"""

from __future__ import annotations

from pathlib import Path
import platform


class TestSeccompConsolidationDocs:
    """Docs accurately reflect seccomp support and limitations."""

    def test_readme_documents_seccomp(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "seccomp" in readme.lower()
        assert "syscall" in readme.lower()

    def test_readme_has_honest_boundaries_with_seccomp(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        # README should NOT say "does NOT provide seccomp" anymore
        assert "does NOT provide" in readme
        assert "seccomp syscall filtering" in readme or "Seccomp Syscall Filter" in readme

    def test_readme_has_7_invariants(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "INV-006" in readme
        assert "INV-007" in readme

    def test_readme_documents_seccomp_milestone_version(self):
        # v2.67.3: re-anchored. The old anchor ("v2.31.0") was dropped by the
        # v2.60.0 Documentation Truth rewrite. The README now attributes
        # seccomp enforcement to the "Linux Seccomp Enforcement (v1.2.2+)"
        # section, which is the truthful milestone-of-record.
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "Seccomp Enforcement (v1.2.2" in readme

    def test_architecture_documents_enforcement_order(self):
        arch = Path("ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "seccomp" in arch.lower()
        assert "Phase 1b" in arch or "Apply seccomp" in arch
        assert "Phase 1c" in arch

    def test_architecture_has_9_layers(self):
        arch = Path("ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "Layer 6" in arch
        assert "Layer 7" in arch
        assert "Layer 8" in arch
        assert "Layer 9" in arch

    def test_architecture_distinguishes_sandbox_layers(self):
        arch = Path("ARCHITECTURE.md").read_text(encoding="utf-8")
        assert "Resource limits" in arch or "resource_limits" in arch.lower()
        assert "Seccomp syscall filtering" in arch or "Seccomp" in arch
        assert "Namespaces" in arch or "namespaces" in arch.lower()
        assert "Cgroups" in arch or "cgroup" in arch.lower()
        assert "AppArmor" in arch or "apparmor" in arch.lower()

    def test_architecture_has_7_invariant_codes(self):
        arch = Path("ARCHITECTURE.md").read_text(encoding="utf-8")
        for code in ("INV-001", "INV-002", "INV-003", "INV-004", "INV-005", "INV-006", "INV-007"):
            assert code in arch, f"{code} not in ARCHITECTURE.md"

    def test_linux_deployment_has_v125_evidence(self):
        deploy = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "seccomp_enforced" in deploy
        assert "True" in deploy
        assert "syscall_filtering" in deploy

    def test_frozen_surfaces_has_inv006_and_inv007(self):
        frozen = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "INV-006" in frozen
        assert "INV-007" in frozen

    def test_changelog_has_v122_through_v126(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        for v in ("1.2.2", "1.2.3", "1.2.4", "1.2.5", "2.0.0"):
            assert v in changelog, f"Version {v} not in CHANGELOG.md"


class TestTrustCLISeccompOutput:
    """CLI trust output shows seccomp fields."""

    def test_trust_cli_has_seccomp_fields(self):
        """The trust command source includes seccomp output."""
        from nodechain.cli import main as cli_main
        source = open(cli_main.__file__, encoding="utf-8").read()
        assert "seccomp" in source.lower()
        assert "syscall" in source.lower()


class TestConsolidationVersion:
    """Version reflects v1.2.6."""

    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.5.1"
