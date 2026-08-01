"""Tests for package trust levels and execution-boundary policy.

AC1: Explicit trust levels: built_in, local_trusted, local_untrusted, remote_untrusted.
AC2: Dependency isolation strategy documented and partially enforced.
AC3: Import allow/deny policy for package code.
AC4: Filesystem access policy: none, package_read_only, workspace_read, workspace_write.
AC5: Subprocess/network enforcement strategy.
AC6: Report records trust level and execution isolation mode.
AC7: Existing 858 tests remain green.
"""

import pytest
from pathlib import Path

from nodechain.sdk.trust import (
    TrustLevel, FilesystemPolicy, ImportPolicy, ExecutionPolicy,
    resolve_trust_level, get_execution_policy, check_filesystem_access,
    resolve_trust_from_package, DEFAULT_POLICIES,
)


class TestTrustLevels:
    """AC1: Explicit trust levels."""

    def test_four_trust_levels_exist(self):
        """AC1: All four trust levels defined."""
        assert TrustLevel.BUILT_IN.value == "built_in"
        assert TrustLevel.LOCAL_TRUSTED.value == "local_trusted"
        assert TrustLevel.LOCAL_UNTRUSTED.value == "local_untrusted"
        assert TrustLevel.REMOTE_UNTRUSTED.value == "remote_untrusted"

    def test_resolve_built_in(self):
        """AC1: Core nodes are built_in."""
        tl = resolve_trust_level("goal_interpreter", origin="built_in")
        assert tl == TrustLevel.BUILT_IN

    def test_resolve_local_trusted(self):
        """AC1: Policy-passing registry nodes are local_trusted."""
        tl = resolve_trust_level(
            "echo_node", is_registry=True, policy_allowed=True, origin="local_registry",
        )
        assert tl == TrustLevel.LOCAL_TRUSTED

    def test_resolve_local_untrusted(self):
        """AC1: Policy-failing registry nodes are local_untrusted."""
        tl = resolve_trust_level(
            "future_node", is_registry=True, policy_allowed=False, origin="local_registry",
        )
        assert tl == TrustLevel.LOCAL_UNTRUSTED

    def test_resolve_remote_untrusted(self):
        """AC1: Remote nodes are remote_untrusted."""
        tl = resolve_trust_level(
            "remote_x", is_registry=True, policy_allowed=False, origin="remote",
        )
        assert tl == TrustLevel.REMOTE_UNTRUSTED

    def test_default_policy_not_registry_is_built_in(self):
        """AC1: Non-registry nodes default to built_in."""
        tl = resolve_trust_level("some_node", is_registry=False)
        assert tl == TrustLevel.BUILT_IN


class TestFilesystemPolicy:
    """AC4: Filesystem access policy."""

    def test_built_in_has_workspace_write(self):
        """AC4: Built-in nodes can write workspace."""
        policy = get_execution_policy(TrustLevel.BUILT_IN)
        assert policy.filesystem == FilesystemPolicy.WORKSPACE_WRITE

    def test_local_trusted_has_package_read_only(self):
        """AC4: Trusted registry nodes read package dir only."""
        policy = get_execution_policy(TrustLevel.LOCAL_TRUSTED)
        assert policy.filesystem == FilesystemPolicy.PACKAGE_READ_ONLY

    def test_untrusted_has_none(self):
        """AC4: Untrusted nodes have no filesystem access."""
        policy = get_execution_policy(TrustLevel.LOCAL_UNTRUSTED)
        assert policy.filesystem == FilesystemPolicy.NONE

    def test_package_read_allows_own_dir(self):
        """AC4: Package read allows access to own directory."""
        ok, _ = check_filesystem_access(
            TrustLevel.LOCAL_TRUSTED,
            "nodes/echo_node/implementation.py",
            "nodes/echo_node",
        )
        assert ok is True

    def test_package_read_blocks_outside(self):
        """AC4: Package read blocks access outside package."""
        ok, reason = check_filesystem_access(
            TrustLevel.LOCAL_TRUSTED,
            "data/chain_state.db",
            "nodes/echo_node",
        )
        assert ok is False
        assert "outside" in reason.lower()

    def test_none_blocks_everything(self):
        """AC4: None policy blocks all access."""
        ok, reason = check_filesystem_access(
            TrustLevel.LOCAL_UNTRUSTED,
            "anything",
        )
        assert ok is False
        assert "blocked" in reason.lower()

    def test_workspace_write_allows(self):
        """AC4: Workspace write allows access."""
        ok, _ = check_filesystem_access(
            TrustLevel.BUILT_IN,
            "data/chain_state.db",
        )
        assert ok is True


class TestImportPolicy:
    """AC3: Import allow/deny policy."""

    def test_default_allows_stdlib(self):
        """AC3: Default allows standard library."""
        ip = ImportPolicy()
        ok, _ = ip.is_import_allowed("json")
        assert ok is True

    def test_default_allows_nodechain(self):
        """AC3: Default allows nodechain imports."""
        ip = ImportPolicy()
        ok, _ = ip.is_import_allowed("nodechain.core.state")
        assert ok is True

    def test_deny_list_blocks(self):
        """AC3: Deny list blocks matching modules."""
        ip = ImportPolicy(denied_modules=["subprocess", "socket"])
        ok, reason = ip.is_import_allowed("subprocess")
        assert ok is False
        assert "deny list" in reason

    def test_deny_list_blocks_submodules(self):
        """AC3: Deny list blocks submodules."""
        ip = ImportPolicy(denied_modules=["subprocess"])
        ok, _ = ip.is_import_allowed("subprocess.run")
        assert ok is False

    def test_allow_list_restricts(self):
        """AC3: Allow list restricts to listed modules."""
        ip = ImportPolicy(allowed_modules=["json", "nodechain"])
        ok, _ = ip.is_import_allowed("json")
        assert ok is True
        ok, _ = ip.is_import_allowed("os")
        assert ok is False

    def test_no_third_party_blocks(self):
        """AC3: Disabling third_party blocks non-stdlib."""
        ip = ImportPolicy(allow_third_party=False)
        ok, _ = ip.is_import_allowed("httpx")
        assert ok is False

    def test_dangerous_modules_flagged(self):
        """AC3: Dangerous modules are flagged even when allowed."""
        ip = ImportPolicy()
        ok, reason = ip.is_import_allowed("subprocess")
        assert ok is True  # Default allows
        assert "dangerous" in reason

    def test_untrusted_policy_has_restrictions(self):
        """AC3: Local untrusted execution policy restricts imports."""
        policy = DEFAULT_POLICIES[TrustLevel.LOCAL_UNTRUSTED]
        ip = policy.import_policy
        ok, _ = ip.is_import_allowed("subprocess")
        assert ok is False

    def test_remote_policy_restricts_os(self):
        """AC3: Remote untrusted policy restricts even os."""
        policy = DEFAULT_POLICIES[TrustLevel.REMOTE_UNTRUSTED]
        ip = policy.import_policy
        ok, _ = ip.is_import_allowed("os")
        assert ok is False


class TestSubprocessNetworkPolicy:
    """AC5: Subprocess/network enforcement strategy."""

    def test_built_in_allows_subprocess(self):
        """AC5: Built-in nodes can use subprocess."""
        policy = get_execution_policy(TrustLevel.BUILT_IN)
        assert policy.allow_subprocess is True

    def test_built_in_allows_network(self):
        """AC5: Built-in nodes can use network."""
        policy = get_execution_policy(TrustLevel.BUILT_IN)
        assert policy.allow_network is True

    def test_local_trusted_blocks_subprocess(self):
        """AC5: Trusted registry nodes cannot use subprocess."""
        policy = get_execution_policy(TrustLevel.LOCAL_TRUSTED)
        assert policy.allow_subprocess is False

    def test_local_trusted_blocks_network(self):
        """AC5: Trusted registry nodes cannot use network."""
        policy = get_execution_policy(TrustLevel.LOCAL_TRUSTED)
        assert policy.allow_network is False

    def test_untrusted_blocks_all(self):
        """AC5: Untrusted nodes block everything."""
        policy = get_execution_policy(TrustLevel.LOCAL_UNTRUSTED)
        assert policy.allow_subprocess is False
        assert policy.allow_network is False

    def test_isolation_mode_in_process_for_trusted(self):
        """AC5: Trusted code runs in-process."""
        policy = get_execution_policy(TrustLevel.LOCAL_TRUSTED)
        assert policy.isolation_mode == "in_process"

    def test_isolation_mode_subprocess_for_untrusted(self):
        """AC5: Untrusted code targeted for subprocess isolation."""
        policy = get_execution_policy(TrustLevel.LOCAL_UNTRUSTED)
        assert policy.isolation_mode == "subprocess"


class TestExecutionPolicySerialization:
    """Policy can be serialized for report output."""

    def test_to_dict(self):
        """Execution policy serializes correctly."""
        policy = get_execution_policy(TrustLevel.LOCAL_TRUSTED)
        d = policy.to_dict()
        assert d["trust_level"] == "local_trusted"
        assert d["filesystem"] == "package_read_only"
        assert d["allow_subprocess"] is False
        assert d["allow_network"] is False
        assert d["isolation_mode"] == "in_process"


class TestTrustResolutionFromPackage:
    """Trust resolution from actual packages."""

    def test_echo_node_is_local_trusted(self):
        """Echo node passes policy and is local_trusted."""
        tl = resolve_trust_from_package("echo_node", Path("nodes/echo_node"))
        assert tl == TrustLevel.LOCAL_TRUSTED

    def test_future_node_is_local_untrusted(self):
        """Future node fails version gate and is local_untrusted."""
        tl = resolve_trust_from_package("future_node", Path("nodes/future_node"))
        assert tl == TrustLevel.LOCAL_UNTRUSTED

    def test_no_package_is_built_in(self):
        """No package path means built_in."""
        tl = resolve_trust_from_package("some_built_in", None)
        assert tl == TrustLevel.BUILT_IN


class TestLoaderTrustLevels:
    """Loader records trust levels for loaded nodes."""

    def test_loader_records_trust(self):
        """Loader stores trust level after load."""
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        loader.load("echo_node")
        trust = loader.trust_levels
        assert "echo_node" in trust
        assert trust["echo_node"] == TrustLevel.LOCAL_TRUSTED

    def test_loader_records_all_trust_levels(self):
        """Loader records trust for multiple nodes.
        v2.45.0: uppercase_node denied by admission — test echo_node only."""
        from nodechain.sdk.loader import NodeLoader
        loader = NodeLoader()
        loader.load("echo_node")
        trust = loader.trust_levels
        assert trust["echo_node"] == TrustLevel.LOCAL_TRUSTED
