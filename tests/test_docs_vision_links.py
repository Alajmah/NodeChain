"""Documentation drift guardrails (v2.67.3).

Prevents the documentation drift problem from recurring by verifying
that the canonical documents remain internally consistent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent


@pytest.fixture
def readme():
    return (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")


@pytest.fixture
def vision():
    return (PROJECT_ROOT / "VISION.md").read_text(encoding="utf-8")


@pytest.fixture
def architecture():
    return (PROJECT_ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")


@pytest.fixture
def changelog():
    return (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


# ── VISION.md exists and is linked ────────────────────────────────────────

class TestVisionExists:
    def test_vision_md_exists(self):
        assert (PROJECT_ROOT / "VISION.md").exists(), "VISION.md must exist at repo root"

    def test_readme_links_to_vision(self, readme):
        assert "VISION.md" in readme, "README.md must link to VISION.md"

    def test_readme_contains_slogan(self, readme):
        assert "Build a node once" in readme, "README must contain the project slogan"

    def test_vision_contains_slogan(self, vision):
        assert "Build a node once" in vision, "VISION.md must contain the project slogan"
        assert "Govern it forever" in vision
        assert "Reuse it everywhere" in vision


# ── No trademarked term ──────────────────────────────────────────────────

class TestNoTrademarkedTerm:
    def test_no_trademarked_term_in_vision(self, vision):
        """The trademarked building-block term must never appear in docs."""
        lower = vision.lower()
        assert "lego" not in lower, "VISION.md must not use the trademarked term"

    def test_no_trademarked_term_in_readme(self, readme):
        lower = readme.lower()
        assert "lego" not in lower, "README.md must not use the trademarked term"


# ── ARCHITECTURE.md is explicitly historical ─────────────────────────────

class TestArchitectureHistorical:
    def test_architecture_declares_historical(self, architecture):
        assert "HISTORICAL" in architecture.upper() or "historical" in architecture.lower(), \
            "ARCHITECTURE.md must declare itself as a historical document"

    def test_architecture_references_vision(self, architecture):
        assert "VISION.md" in architecture, \
            "ARCHITECTURE.md must reference VISION.md as the strategic source of truth"

    def test_vision_describes_architecture_as_historical(self, vision):
        assert "historical" in vision.lower(), \
            "VISION.md must describe ARCHITECTURE.md as historical"


# ── Version consistency ──────────────────────────────────────────────────

class TestVersionInDocs:
    def test_vision_contains_current_version(self, vision):
        from nodechain import __version__
        assert __version__ in vision, \
            f"VISION.md must contain the current version ({__version__})"

    def test_changelog_has_latest_version(self, changelog):
        from nodechain import __version__
        # The changelog should have the current version as a heading
        assert f"[{__version__}]" in changelog or f"## [{__version__}]" in changelog, \
            f"CHANGELOG must have an entry for v{__version__}"


# ── Composable terminology ───────────────────────────────────────────────

class TestComposableTerminology:
    def test_vision_uses_composable(self, vision):
        """VISION.md should use 'composable' as the primary term."""
        assert "composable" in vision.lower(), \
            "VISION.md must use 'composable' as the primary terminology"

    def test_vision_defines_harness_node(self, vision):
        """VISION.md must define what a Harness Node is."""
        assert "Harness Node" in vision, \
            "VISION.md must define the Harness Node concept"


# ── New docs exist ───────────────────────────────────────────────────────

class TestNewDocsExist:
    def test_reviewer_guide_exists(self):
        assert (PROJECT_ROOT / "docs" / "reviewer-guide.md").exists(), \
            "docs/reviewer-guide.md must exist"

    def test_node_package_walkthrough_exists(self):
        assert (PROJECT_ROOT / "docs" / "node-package-walkthrough.md").exists(), \
            "docs/node-package-walkthrough.md must exist"
