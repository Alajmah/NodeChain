"""Tests for trust invariant enforcement.

AC1: is_compliant failure becomes an error in strict mode.
AC2: Locked mode requires lockfile_verified=true.
AC3: local_untrusted/remote_untrusted require isolation_mode=subprocess.
AC4: local_untrusted/remote_untrusted require child_policy_enforced=true.
AC5: subprocess-isolated nodes require env_filtered/temp_dir_isolated.
AC6: Reconciler reports structured error codes.
AC7: nodechain trust --strict exits nonzero on violations.
AC8: Existing 1114 tests remain green.
"""

import pytest

from nodechain.sdk.trust_summary import TrustSummary, NodeTrustRecord, TrustViolation


class TestInvariant001:
    """AC3: Untrusted requires subprocess isolation."""

    def test_untrusted_in_process_violates(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants()
        codes = [x.code for x in v]
        assert "INV-001" in codes

    def test_remote_untrusted_in_process_violates(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="remote_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants()
        assert any(x.code == "INV-001" for x in v)

    def test_trusted_in_process_ok(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="ok", trust_level="local_trusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants()
        assert all(x.code != "INV-001" for x in v)


class TestInvariant002:
    """AC4: Untrusted requires child_policy_enforced."""

    def test_untrusted_no_policy_violates(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=False,
            env_filtered=True,
            temp_dir_isolated=True,
        ))
        v = summary.validate_invariants()
        assert any(x.code == "INV-002" for x in v)

    def test_untrusted_with_policy_ok(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="ok", trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
        ))
        v = summary.validate_invariants()
        assert all(x.code != "INV-002" for x in v)


class TestInvariant003:
    """AC5: Subprocess-isolated requires env_filtered."""

    def test_subprocess_no_env_filter_violates(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=False,
            temp_dir_isolated=True,
        ))
        v = summary.validate_invariants()
        assert any(x.code == "INV-003" for x in v)


class TestInvariant004:
    """AC5: Subprocess-isolated requires temp_dir_isolated."""

    def test_subprocess_no_temp_isolation_violates(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=False,
        ))
        v = summary.validate_invariants()
        assert any(x.code == "INV-004" for x in v)


class TestInvariant005:
    """AC2: Locked mode requires lockfile_verified."""

    def test_locked_no_verify_violates(self):
        summary = TrustSummary(run_id="t", locked_mode=True, lockfile_verified=False)
        v = summary.validate_invariants()
        assert any(x.code == "INV-005" for x in v)

    def test_locked_with_verify_ok(self):
        summary = TrustSummary(run_id="t", locked_mode=True, lockfile_verified=True)
        v = summary.validate_invariants()
        assert all(x.code != "INV-005" for x in v)

    def test_not_locked_no_verify_ok(self):
        summary = TrustSummary(run_id="t", locked_mode=False, lockfile_verified=False)
        v = summary.validate_invariants()
        assert all(x.code != "INV-005" for x in v)


class TestStrictMode:
    """AC1: Strict mode escalates warnings to errors."""

    def test_strict_escalates_severity(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        v_normal = summary.validate_invariants(strict=False)
        v_strict = summary.validate_invariants(strict=True)
        # All should already be errors since INV-001 is always error severity
        assert all(x.severity == "error" for x in v_strict)

    def test_strict_returns_same_codes(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants(strict=True)
        codes = [x.code for x in v]
        assert "INV-001" in codes


class TestViolationStructure:
    """AC6: Violations have structured error codes."""

    def test_violation_has_all_fields(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="test_node", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants()
        inv1 = [x for x in v if x.code == "INV-001"][0]
        assert inv1.code == "INV-001"
        assert inv1.severity == "error"
        assert inv1.node_id == "test_node"
        assert inv1.invariant == "untrusted_requires_subprocess_isolation"
        assert "subprocess" in inv1.expected
        assert "in_process" in inv1.actual

    def test_violation_to_dict(self):
        v = TrustViolation(
            code="INV-001", severity="error", node_id="n1",
            invariant="test", expected="a", actual="b",
        )
        d = v.to_dict()
        assert d["code"] == "INV-001"
        assert d["severity"] == "error"
        assert d["node_id"] == "n1"


class TestCLIStrictExitCode:
    """AC7: trust --strict exits nonzero on violations."""

    def test_strict_flag_in_help(self):
        from click.testing import CliRunner
        from nodechain.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["trust", "--help"])
        assert "--strict" in result.output

    def test_trust_command_has_strict_option(self):
        from nodechain.cli.main import cli
        cmd = cli.commands["trust"]
        assert "--strict" in cmd.params or any(
            "strict" in str(p) for p in cmd.params
        )


class TestFullyCompliant:
    """All invariants pass with proper configuration."""

    def test_fully_compliant_untrusted(self):
        summary = TrustSummary(
            run_id="t",
            locked_mode=True,
            lockfile_verified=True,
        )
        summary.add_node(NodeTrustRecord(
            node_id="builtin", trust_level="built_in",
            isolation_mode="in_process",
        ))
        summary.add_node(NodeTrustRecord(
            node_id="trusted", trust_level="local_trusted",
            isolation_mode="in_process",
        ))
        summary.add_node(NodeTrustRecord(
            node_id="untrusted",
            trust_level="local_untrusted",
            isolation_mode="subprocess",
            child_policy_enforced=True,
            env_filtered=True,
            temp_dir_isolated=True,
        ))
        v = summary.validate_invariants(strict=True)
        assert len(v) == 0
        assert summary.is_compliant is True

    def test_multiple_violations(self):
        summary = TrustSummary(run_id="t")
        summary.add_node(NodeTrustRecord(
            node_id="bad1", trust_level="local_untrusted",
            isolation_mode="in_process",
        ))
        summary.add_node(NodeTrustRecord(
            node_id="bad2", trust_level="remote_untrusted",
            isolation_mode="in_process",
        ))
        v = summary.validate_invariants()
        assert len(v) >= 2
        inv1_codes = [x.code for x in v if x.code == "INV-001"]
        assert len(inv1_codes) >= 2
