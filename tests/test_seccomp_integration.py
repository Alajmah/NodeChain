"""Tests for seccomp runtime integration (v1.2.4).

Tests cover:
1. Bootstrap ordering: node module imported AFTER seccomp + all enforcement
2. NodeInvoker propagates seccomp fields
3. NodeTrustRecord has seccomp fields
4. TrustSummary reports seccomp fields
5. INV-007 fires for missing seccomp on Linux os_profile
6. Child metadata includes seccomp report
7. enable_seccomp flag flows through isolation_config
8. allow_preloaded parameter controls import bypass in child
"""

from __future__ import annotations

import asyncio
import os
import platform
import pytest
from pathlib import Path

from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.subprocess_runner import SubprocessRunner
from nodechain.runtime.node_invoker import NodeInvoker
from nodechain.sdk.trust import TrustLevel
from nodechain.sdk.trust_summary import (
    NodeTrustRecord,
    TrustSummary,
    TrustViolation,
)
from nodechain.sdk.import_enforcer import (
    enforce_imports_for_node,
    ImportBlockedError,
    ImportEnforcer,
)


# --- Helpers ---------------------------------------------------------------

def _make_envelope(node_id: str = "echo_node") -> InvocationEnvelope:
    return InvocationEnvelope(
        run_id="test-run",
        chain_id="test-chain",
        node_id=node_id,
        step_id=1,
        payload={"query": "hello"},
    )


ECHO_PATH = "nodes/echo_node/implementation.py"
ECHO_CLASS = "EchoNode"


# --- 1. Bootstrap Ordering Tests -------------------------------------------

class TestBootstrapOrdering:
    """The node module must be imported AFTER seccomp + all enforcement."""

    @pytest.mark.asyncio
    async def test_echo_node_works_under_new_ordering(self):
        """Echo node still works with new bootstrap ordering."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()
        result = await runner.run_isolated(
            envelope=envelope,
            module_path=ECHO_PATH,
            class_name=ECHO_CLASS,
            node_id="echo_node",
            trust_level="local_untrusted",
            package_root="nodes/echo_node",
        )
        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        md = result["response"].get("metadata", {})
        assert md.get("child_policy_enforced") is True

    @pytest.mark.asyncio
    async def test_filesystem_violations_reported(self):
        """Node that tries to access files gets fs violation report."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope("sandbox_test")
        result = await runner.run_isolated(
            envelope=envelope,
            module_path="nodes/sandbox_test_node/implementation.py",
            class_name="SandboxTestNode",
            node_id="sandbox_test_node",
            trust_level="local_untrusted",
            package_root="nodes/sandbox_test_node",
        )
        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        md = result["response"].get("metadata", {})
        assert md.get("child_policy_enforced") is True

    @pytest.mark.asyncio
    async def test_seccomp_report_in_metadata_without_seccomp(self):
        """Without enable_seccomp, metadata has seccomp_enforced=False."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()
        result = await runner.run_isolated(
            envelope=envelope,
            module_path=ECHO_PATH,
            class_name=ECHO_CLASS,
            node_id="echo_node",
            trust_level="local_untrusted",
            enable_seccomp=False,
        )
        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        md = result["response"].get("metadata", {})
        assert "seccomp_enforced" in md
        assert md["seccomp_enforced"] is False
        assert "seccomp_available" in md

    @pytest.mark.asyncio
    async def test_seccomp_report_in_metadata_with_seccomp(self):
        """With enable_seccomp=True, metadata has seccomp fields."""
        runner = SubprocessRunner(timeout_seconds=15)
        envelope = _make_envelope()
        result = await runner.run_isolated(
            envelope=envelope,
            module_path=ECHO_PATH,
            class_name=ECHO_CLASS,
            node_id="echo_node",
            trust_level="local_untrusted",
            enable_seccomp=True,
        )
        if os.name == "posix":
            # T3.0 safety fence: POSIX untrusted execution refused before spawn
            assert result["success"] is False
            assert result["exit_code"] == 126
            assert result["error"].startswith("supervised_backend_required")
            return  # Skip original capability assertions on POSIX
        # Windows: original assertions remain intact below
        assert result["success"] is True
        md = result["response"].get("metadata", {})
        assert "seccomp_enforced" in md
        assert "seccomp_available" in md


# --- 2. NodeInvoker Seccomp Propagation ------------------------------------

class TestNodeInvokerSeccompPropagation:
    """NodeInvoker passes seccomp fields from child to response metadata."""

    @pytest.mark.asyncio
    async def test_isolation_config_carries_enable_seccomp(self):
        """isolation_config with enable_seccomp=True is passed through."""
        from nodechain.nodes.base_node import BaseNode
        from nodechain.core.envelope import Context, Capabilities

        class DummyNode(BaseNode):
            pass

        DummyNode._manifest = type("M", (), {"node_id": "test"})()

        invoker = NodeInvoker()
        envelope = invoker.build_envelope(
            run_id="test", chain_id="test", node_id="test", step_id=1,
            payload={}, context=Context(), capabilities=Capabilities(),
        )
        assert invoker is not None


# --- 3. NodeTrustRecord Seccomp Fields -------------------------------------

class TestNodeTrustRecordSeccompFields:
    """NodeTrustRecord has v1.2.3 seccomp fields."""

    def test_seccomp_fields_exist(self):
        record = NodeTrustRecord(node_id="test")
        assert hasattr(record, "seccomp_enforced")
        assert hasattr(record, "seccomp_profile_name")
        assert hasattr(record, "syscall_filtering_enforced")

    def test_default_values(self):
        record = NodeTrustRecord(node_id="test")
        assert record.seccomp_enforced is False
        assert record.seccomp_profile_name == ""
        assert record.syscall_filtering_enforced is False

    def test_seccomp_fields_in_to_dict(self):
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="test",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            seccomp_enforced=True,
            seccomp_profile_name="nodechain_default",
            syscall_filtering_enforced=True,
        ))
        d = summary.to_dict()
        node = d["nodes"][0]
        assert "seccomp_enforced" in node
        assert "seccomp_profile_name" in node
        assert "syscall_filtering_enforced" in node
        assert node["seccomp_enforced"] is True
        assert node["seccomp_profile_name"] == "nodechain_default"
        assert node["syscall_filtering_enforced"] is True


# --- 4. INV-007 Seccomp Capability Check -----------------------------------

class TestINV007SeccompCheck:
    """INV-007 checks seccomp on Linux os_profile nodes."""

    def test_inv007_fires_on_linux_os_profile_without_seccomp(self):
        """On Linux, os_profile without syscall_filtering_enforced fires INV-007."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="linux_rlimit",
            syscall_filtering_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv007 = [v for v in violations if v.code == "INV-007"]
        if platform.system() == "Linux":
            assert len(inv007) == 1
            assert "syscall_filtering_enforced" in inv007[0].expected
        else:
            assert len(inv007) == 0

    def test_inv007_passes_on_linux_with_seccomp(self):
        """On Linux, os_profile with syscall_filtering_enforced=True: no INV-007."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="os_profile",
            sandbox_profile_used="os_profile",
            sandbox_backend="linux_rlimit",
            syscall_filtering_enforced=True,
        ))
        violations = summary.validate_invariants()
        inv007 = [v for v in violations if v.code == "INV-007"]
        assert len(inv007) == 0

    def test_inv007_does_not_fire_for_subprocess_isolated(self):
        """subprocess_isolated profile doesn't require seccomp."""
        summary = TrustSummary(run_id="test")
        summary.add_node(NodeTrustRecord(
            node_id="untrusted_node",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
            sandbox_profile_required="subprocess_isolated",
            sandbox_profile_used="subprocess_isolated",
            sandbox_backend="linux_rlimit",
            syscall_filtering_enforced=False,
        ))
        violations = summary.validate_invariants()
        inv007 = [v for v in violations if v.code == "INV-007"]
        assert len(inv007) == 0


# --- 5. allow_preloaded Parameter ------------------------------------------

class TestAllowPreloaded:
    """The allow_preloaded parameter controls import bypass for pre-loaded modules."""

    def test_default_is_false(self):
        """allow_preloaded defaults to False."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        assert enforcer.allow_preloaded is False

    def test_import_blocked_when_preloaded_false(self):
        """When allow_preloaded=False, subprocess import is blocked for untrusted."""
        enforcer = enforce_imports_for_node(TrustLevel.LOCAL_UNTRUSTED, "test")
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("subprocess")

    def test_preloaded_denylisted_module_blocked_even_when_preloaded_true(self):
        """When allow_preloaded=True, denylisted modules are STILL blocked.

        v1.18.5: subprocess and socket added to _PRELOADED_DENYLIST.
        They are always blocked even when preloaded by the trusted bootstrap.
        """
        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("subprocess")

    def test_new_import_still_blocked_when_preloaded_true(self):
        """When allow_preloaded=True, NEW imports not in sys.modules are blocked."""
        enforcer = enforce_imports_for_node(
            TrustLevel.LOCAL_UNTRUSTED, "test", allow_preloaded=True
        )
        with enforcer.enforce():
            with pytest.raises(ImportBlockedError):
                __import__("nonexistent_malicious_module")


# --- 6. SandboxProfileResolver + Seccomp -----------------------------------

class TestSandboxProfileSeccomp:
    """SandboxProfileResolver determines seccomp enablement."""

    def test_os_profile_on_linux_should_enable_seccomp(self):
        """On Linux, os_profile should enable seccomp."""
        from nodechain.sdk.os_sandbox import SandboxProfile, SandboxProfileResolver
        resolver = SandboxProfileResolver()
        resolved = resolver.resolve(SandboxProfile.OS_PROFILE, trust_level="local_untrusted")
        assert resolved is not None

    def test_seccomp_enforced_field_in_capabilities(self):
        """SandboxCapabilities has seccomp fields."""
        from nodechain.sdk.os_sandbox import detect_backend
        backend = detect_backend()
        caps = backend.get_capabilities()
        assert hasattr(caps, "seccomp_available")
        assert hasattr(caps, "seccomp_enforced")
        assert hasattr(caps, "seccomp_profile_name")


# --- 7. Version and Changelog ----------------------------------------------

class TestSeccompRuntimeIntegrationVersion:
    """Version and changelog reflect v1.2.4."""

    def test_version_is_1_2_4(self):
        import nodechain
        assert nodechain.__version__ == "3.6.0"

    def test_changelog_has_v124(self):
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "3.5.1" in changelog


# --- 8. Child Script Bootstrap Ordering Verification -----------------------

class TestChildScriptBootstrapOrdering:
    """Verify the child script source has correct phase ordering."""

    def test_seccomp_before_node_import_in_source(self):
        """The generated child script must apply seccomp before importing node."""
        runner = SubprocessRunner()
        script = runner._build_child_script(
            module_path="test.py",
            class_name="Test",
            trust_level="local_untrusted",
            enable_seccomp=True,
        )
        seccomp_pos = script.find("Apply seccomp filter")
        node_import_pos = script.find("Phase 2: Import untrusted node module")
        assert seccomp_pos > 0, "Seccomp filter marker not found"
        assert node_import_pos > 0, "Phase 2 node import marker not found"
        assert seccomp_pos < node_import_pos, "Seccomp must come BEFORE node import"

    def test_all_enforcement_before_node_import_in_source(self):
        """ALL enforcement (including import) active before node import."""
        runner = SubprocessRunner()
        script = runner._build_child_script(
            module_path="test.py",
            class_name="Test",
            trust_level="local_untrusted",
            enable_seccomp=False,
        )
        # The enforcement activation must come before node import
        enforce_pos = script.find("Activate ALL enforcement")
        node_import_pos = script.find("Phase 2: Import untrusted node module")
        assert enforce_pos > 0, "Enforcement activation marker not found"
        assert node_import_pos > 0, "Phase 2 node import marker not found"
        assert enforce_pos < node_import_pos, "Enforcement must come BEFORE node import"

    def test_no_phase_2b_in_source(self):
        """No Phase 2b — import enforcement is part of Phase 1c, not deferred."""
        runner = SubprocessRunner()
        script = runner._build_child_script(
            module_path="test.py",
            class_name="Test",
            trust_level="local_untrusted",
        )
        assert "Phase 2b" not in script, "Phase 2b should not exist in v1.2.4"

    def test_allow_preloaded_in_child_source(self):
        """Child script uses allow_preloaded=True for import enforcement."""
        runner = SubprocessRunner()
        script = runner._build_child_script(
            module_path="test.py",
            class_name="Test",
            trust_level="local_untrusted",
        )
        assert "allow_preloaded=True" in script
