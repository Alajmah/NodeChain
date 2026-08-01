"""Release-truth guard test (v2.54.0).

Verifies that nodechain.__version__, pyproject.toml, docs/ci.md, README.md
status line, and CHANGELOG.md all agree on the current version. Prevents
the drift that accumulated from v2.31.0 through v2.53.0.
"""

from __future__ import annotations

import re
from pathlib import Path

import nodechain


REPO_ROOT = Path(__file__).parent.parent


def _extract_version_from_pyproject(text: str) -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "pyproject.toml must have a version field"
    return m.group(1)


def _extract_version_from_ci_md(text: str) -> str:
    m = re.search(r"version is currently `([^`]+)`", text)
    assert m, "docs/ci.md must state the current version"
    return m.group(1)


def _extract_version_from_readme(text: str) -> str:
    m = re.search(r"\*\*(v[\d.]+)", text[text.find("## Status"):text.find("## Status") + 200])
    assert m, "README.md must have a Status section with a version"
    return m.group(1).lstrip("v")


def _extract_latest_changelog_version(text: str) -> str:
    m = re.search(r"##\s*\[([\d.]+)\]", text)
    assert m, "CHANGELOG.md must have at least one version entry"
    return m.group(1)


def test_pyproject_matches_runtime():
    """pyproject.toml version must match nodechain.__version__."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert _extract_version_from_pyproject(pyproject) == nodechain.__version__


def test_ci_docs_match_runtime():
    """docs/ci.md current-version statement must match nodechain.__version__."""
    ci_md = (REPO_ROOT / "docs" / "ci.md").read_text()
    assert _extract_version_from_ci_md(ci_md) == nodechain.__version__


def test_readme_status_matches_runtime():
    """README.md Status section must match nodechain.__version__."""
    readme = (REPO_ROOT / "README.md").read_text()
    assert _extract_version_from_readme(readme) == nodechain.__version__


def test_changelog_latest_matches_runtime():
    """CHANGELOG.md latest entry must match nodechain.__version__."""
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text()
    assert _extract_latest_changelog_version(changelog) == nodechain.__version__


def test_architecture_md_current_version_matches_runtime():
    """ARCHITECTURE.md historical-document note must state the current version."""
    arch = (REPO_ROOT / "ARCHITECTURE.md").read_text()
    m = re.search(r"The current version is v([\d.]+)\b", arch)
    assert m, "ARCHITECTURE.md must state a current version"
    assert m.group(1) == nodechain.__version__
