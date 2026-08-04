"""Release version guard.

Ensures runtime version is consistent across all surfaces.
This test should be updated to the target version before each release.
"""

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_VERSION = "3.6.0"


class TestReleaseVersionGuard:
    """Runtime version must be consistent across all surfaces."""

    def test_init_version(self):
        from nodechain import __version__
        assert __version__ == EXPECTED_VERSION

    def test_pyproject_version(self):
        with open(ROOT / "pyproject.toml", "rb") as f:
            data = tomllib.load(f)
        assert data["project"]["version"] == EXPECTED_VERSION

    def test_version_matches_expected_constant(self):
        """The EXPECTED_VERSION constant in this file must match release."""
        assert EXPECTED_VERSION == "3.6.0"

    def test_cli_version_output(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert EXPECTED_VERSION in result.output

    def test_policy_enforcer_version(self):
        from nodechain.sdk.policy_enforcer import PackagePolicyEnforcer
        enforcer = PackagePolicyEnforcer()
        assert enforcer.runtime_version == EXPECTED_VERSION

    def test_lockfile_version(self, tmp_path):
        from nodechain.sdk.lockfile import generate_lockfile
        out = tmp_path / "test.lock.json"
        lf = generate_lockfile(output_path=out)
        assert lf["nodechain_version"] == EXPECTED_VERSION
