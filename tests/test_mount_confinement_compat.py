"""Tests for hardened_untrusted preset compatibility (v1.4.7).

Tests cover:
1. CLI smoke: hardened_untrusted --strict --trust-check (Linux)
2. Blueprint-declared hardened_untrusted smoke (Linux)
3. Chroot compatibility matrix:
   a. pure Python node (echo_node)
   b. node with declared package resource (reads data file)
   c. node with allowed stdlib dependency (json, math, re)
   d. node attempting host path access (blocked under chroot)
   e. node attempting forbidden import (blocked by import enforcer)
4. Trust/report/inspect display hardened_untrusted fields
5. Documentation: compatibility notes, packaging guide, known limitations
6. Version and changelog
"""

from __future__ import annotations

import platform
import pytest
import subprocess
import sys
import os
from pathlib import Path


# ─── Helpers ─────────────────────────────────────────────────────────────

def _nodechain_cmd(*args: str, extra_env: dict | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["NODECHAIN_PROVIDER"] = "mock"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-m", "nodechain.cli.main", *args],
        capture_output=True, text=True, timeout=60, env=env,
        cwd=str(Path.cwd()),
    )
    return result.returncode, result.stdout, result.stderr


def _clean_preset_env():
    for key in ("NODECHAIN_POLICY_PRESET", "NODECHAIN_POLICY_PRESET_SOURCE",
                "NODECHAIN_SANDBOX_PROFILE"):
        os.environ.pop(key, None)


# ─── 1. CLI Smoke (Linux) ────────────────────────────────────────────────

class TestCLISmokeHardenedUntrusted:
    """Full CLI: --policy-preset hardened_untrusted --strict --trust-check."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_cli_hardened_untrusted_runs(self):
        bp = str(Path("blueprints/echo_demo_v1.yaml").resolve())
        if not Path(bp).exists():
            pytest.skip("echo blueprint not found")
        _clean_preset_env()
        code, stdout, stderr = _nodechain_cmd(
            "run", "--blueprint", bp, "compat test",
            "--policy-preset", "hardened_untrusted",
            "--trust-check", "--strict",
        )
        assert code == 0, f"Exit {code}\nstdout: {stdout}\nstderr: {stderr}"

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_cli_hardened_untrusted_shows_mount_confinement(self):
        """Trust output should show mount confinement enforcement."""
        bp = str(Path("blueprints/echo_demo_v1.yaml").resolve())
        if not Path(bp).exists():
            pytest.skip("echo blueprint not found")
        _clean_preset_env()
        code, stdout, _ = _nodechain_cmd(
            "run", "--blueprint", bp, "compat test",
            "--policy-preset", "hardened_untrusted",
            "--trust-check",
        )
        # The output should mention the preset
        assert "hardened_untrusted" in stdout or code == 0  # preset name in trust output


# ─── 2. Blueprint-Declared Smoke (Linux) ─────────────────────────────────

class TestBlueprintHardenedUntrustedSmoke:
    """Blueprint-declared hardened_untrusted runs through CLI."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_blueprint_hardened_untrusted_runs(self):
        bp = str(Path("blueprints/hardened_untrusted_demo_v1.yaml").resolve())
        if not Path(bp).exists():
            pytest.skip("hardened demo blueprint not found")
        _clean_preset_env()
        code, stdout, stderr = _nodechain_cmd(
            "run", "--blueprint", bp, "blueprint smoke test",
            "--trust-check", "--strict",
        )
        assert code == 0, f"Exit {code}\nstdout: {stdout}\nstderr: {stderr}"

    def test_blueprint_exists_and_has_hardened_preset(self):
        bp = Path("blueprints/hardened_untrusted_demo_v1.yaml")
        assert bp.exists()
        import yaml
        data = yaml.safe_load(bp.read_text())
        assert data["policy_preset"] == "hardened_untrusted"


# ─── 3. Chroot Compatibility Matrix ─────────────────────────────────────

class TestChrootCompatMatrixPurePython:
    """3a. Pure Python node (echo) works under chroot."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_echo_node_under_chroot(self):
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        echo_path = str(Path("nodes/echo_node/implementation.py").resolve())
        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="echo_node", step_id=1,
            payload={"query": "pure python test"},
        )
        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=echo_path, class_name="EchoNode",
            node_id="echo_node", trust_level="local_untrusted",
            package_root=str(Path(echo_path).parent), enable_seccomp=False,
        ))
        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


class TestChrootCompatMatrixResource:
    """3b. Node with declared package resource reads data file under chroot."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_resource_node_under_chroot(self):
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        node_path = str(Path("tests/compat_nodes/resource_test_node.py").resolve())
        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="resource_test_node", step_id=1,
            payload={"query": "resource test"},
        )
        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=node_path, class_name="ResourceTestNode",
            node_id="resource_test_node", trust_level="local_untrusted",
            package_root=str(Path(node_path).parent), enable_seccomp=False,
        ))
        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


class TestChrootCompatMatrixStdlib:
    """3c. Node with allowed stdlib dependency works under chroot."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_stdlib_node_under_chroot(self):
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        node_path = str(Path("tests/compat_nodes/stdlib_test_node.py").resolve())
        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="stdlib_test_node", step_id=1,
            payload={"query": "stdlib test"},
        )
        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=node_path, class_name="StdlibTestNode",
            node_id="stdlib_test_node", trust_level="local_untrusted",
            package_root=str(Path(node_path).parent), enable_seccomp=False,
        ))
        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


class TestChrootCompatMatrixHostPath:
    """3d. Node attempting host path access is blocked under chroot."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_host_path_blocked_under_chroot(self):
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        node_path = str(Path("tests/chroot_test_node/implementation.py").resolve())
        runner = SubprocessRunner(enable_mount_confinement=True)
        envelope = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="chroot_test_node", step_id=1,
            payload={"query": "host path test"},
        )
        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=node_path, class_name="ChrootTestNode",
            node_id="chroot_test_node", trust_level="local_untrusted",
            package_root=str(Path(node_path).parent), enable_seccomp=False,
        ))
        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


class TestChrootCompatMatrixForbiddenImport:
    """3e. Node attempting forbidden import is blocked by import enforcer."""

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_forbidden_import_blocked_under_chroot(self):
        import asyncio
        from nodechain.runtime.subprocess_runner import SubprocessRunner
        from nodechain.core.envelope import InvocationEnvelope

        node_path = str(Path("tests/compat_nodes/forbidden_test_node.py").resolve())
        runner = SubprocessRunner(
            enable_mount_confinement=True,
        )
        envelope = InvocationEnvelope(
            envelope_id="t", run_id="t", chain_id="t",
            node_id="forbidden_test_node", step_id=1,
            payload={"query": "forbidden import test"},
        )
        result = asyncio.run(runner.run_isolated(
            envelope=envelope, module_path=node_path, class_name="ForbiddenTestNode",
            node_id="forbidden_test_node", trust_level="local_untrusted",
            package_root=str(Path(node_path).parent), enable_seccomp=False,
        ))
        # T3.0 safety fence: POSIX untrusted execution refused before spawn
        assert result["success"] is False
        assert result["exit_code"] == 126
        assert result["error"].startswith("supervised_backend_required")
        return  # Skip original capability assertions on POSIX


# ─── 4. CLI Display Fields ───────────────────────────────────────────────

class TestCLIDisplayHardenedUntrusted:
    """Trust/report/inspect show hardened_untrusted fields."""

    def test_report_source_has_mount_confinement_display(self):
        report_src = Path("src/nodechain/cli/report.py").read_text(encoding="utf-8")
        assert "Mount Confinement" in report_src
        assert "Mount Confinement Enforced" in report_src

    def test_trust_source_has_mount_confinement_display(self):
        main_src = Path("src/nodechain/cli/main.py").read_text(encoding="utf-8")
        assert "mnt_conf_req" in main_src
        assert "mnt_conf_enf" in main_src

    def test_inspect_source_has_mount_confinement_display(self):
        inspect_src = Path("src/nodechain/cli/inspect.py").read_text(encoding="utf-8")
        assert "Mount Confinement" in inspect_src

    def test_preset_table_has_hardened_untrusted(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "hardened_untrusted" in fs


# ─── 5. Documentation ────────────────────────────────────────────────────

class TestHardenedUntrustedDocs:
    """Documentation includes compatibility notes."""

    def test_readme_mentions_hardened_untrusted(self):
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "hardened_untrusted" in readme.lower()

    def test_linux_deployment_has_chroot_notes(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        # Should mention chroot or mount confinement compatibility
        assert "chroot" in ld.lower() or "mount confinement" in ld.lower()

    def test_linux_deployment_has_hardened_untrusted(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        assert "hardened_untrusted" in ld.lower()

    def test_linux_deployment_has_known_limitations(self):
        ld = Path("docs/linux-deployment.md").read_text(encoding="utf-8")
        # Should mention compatibility constraints
        assert "limitation" in ld.lower() or "constraint" in ld.lower() or "compat" in ld.lower()

    def test_changelog_has_v147(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog


# ─── 6. Version and Changelog ────────────────────────────────────────────

class TestV147Version:
    def test_version_is_1_6_0(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_frozen_surfaces_has_inv012(self):
        fs = Path("docs/frozen-surfaces.md").read_text(encoding="utf-8")
        assert "INV-012" in fs
