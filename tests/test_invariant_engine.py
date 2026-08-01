"""Direct tests for InvariantEngine — blueprint and runtime invariant enforcement.

Covers:
- Structural: connections, branches, joins, loops, orphans
- Governance: policy coverage, side-effect declarations
- Strict mode: warnings become errors
- Cancellation: wait_for=any requires cancellation_policy, enum validation
- Trace audit: trace metadata, strict-mode escalation
- Valid blueprints pass clean
"""

import os

import pytest

from nodechain.core.blueprint import (
    ChainBlueprint, NodeDef, ConnectionDef, BranchDef, JoinDef, LoopDef,
    GateDef, InvariantDef,
)
from nodechain.runtime.invariant_engine import (
    InvariantEngine, InvariantReport,
    VALID_CANCELLATION_POLICIES, CANCEL_ALLOW_ALL, CANCEL_ON_FIRST,
)


def _make_blueprint(
    nodes=None,
    connections=None,
    branches=None,
    joins=None,
    loops=None,
    gates=None,
    invariants=None,
    trace=None,
    governance=None,
) -> ChainBlueprint:
    _nodes = nodes or [
        NodeDef(node_id="a", node_type="test", position=1),
        NodeDef(node_id="b", node_type="test", position=2),
        NodeDef(node_id="c", node_type="test", position=3),
    ]
    _connections = connections if connections is not None else [
        ConnectionDef(from_node="a", from_port="out", to_node="b", to_port="in"),
        ConnectionDef(from_node="b", from_port="out", to_node="c", to_port="in"),
    ]
    return ChainBlueprint(
        chain_id="test",
        name="Test",
        goal="Test",
        nodes=_nodes,
        connections=_connections,
        branches=branches or [],
        joins=joins or [],
        loops=loops or [],
        gates=gates or [],
        invariants=invariants or [],
        trace=trace or {},
        governance=governance or {},
    )


# ═══════════════════════════════════════════════════════════════════
# Structural invariants (check_blueprint)
# ═══════════════════════════════════════════════════════════════════

class TestValidBlueprints:
    def test_simple_sequential_passes(self):
        report = InvariantEngine().check_blueprint(_make_blueprint())
        assert report.is_valid, report.summary()

    def test_empty_blueprint_passes(self):
        bp = ChainBlueprint(
            chain_id="empty", name="Empty", goal="Test",
            nodes=[NodeDef(node_id="x", node_type="test", position=1)],
            connections=[],
        )
        report = InvariantEngine().check_blueprint(bp)
        assert len(report.errors) == 0

    def test_branch_blueprint_passes(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            nodes=[
                NodeDef(node_id="router", node_type="test", position=1),
                NodeDef(node_id="bio_search", node_type="test", position=2),
                NodeDef(node_id="tech_search", node_type="test", position=3),
                NodeDef(node_id="joiner", node_type="test", position=4),
            ],
            connections=[],
            branches=[
                BranchDef(
                    branch_id="b1", from_node="router",
                    branches={"bio": ["bio_search"], "tech": ["tech_search"]},
                    default_branch="bio",
                ),
            ],
            joins=[
                JoinDef(join_id="j1", to_node="joiner", from_branches=["bio", "tech"]),
            ],
        ))
        assert report.is_valid, report.summary()


class TestConnectionInvariants:
    def test_missing_from_node(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            connections=[
                ConnectionDef(from_node="nonexistent", from_port="out", to_node="b", to_port="in"),
            ],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "connection_source_exists" for v in report.errors)

    def test_missing_to_node(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            connections=[
                ConnectionDef(from_node="a", from_port="out", to_node="ghost", to_port="in"),
            ],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "connection_target_exists" for v in report.errors)


class TestBranchInvariants:
    def test_missing_branch_source(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            branches=[BranchDef(branch_id="b1", from_node="ghost", branches={"x": ["a"]})],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "branch_source_exists" for v in report.errors)

    def test_missing_branch_target(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            branches=[BranchDef(branch_id="b1", from_node="a", branches={"x": ["ghost"]})],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "branch_target_exists" for v in report.errors)

    def test_missing_default_branch(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            branches=[BranchDef(branch_id="b1", from_node="a",
                                branches={"x": ["b"]}, default_branch="nonexistent")],
        ))
        assert any(v.invariant_id == "branch_default_exists" for v in report.warnings)


class TestJoinInvariants:
    def test_missing_join_target(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            joins=[JoinDef(join_id="j1", to_node="ghost", from_branches=["x"])],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "join_target_exists" for v in report.errors)

    def test_missing_join_source_branch(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            joins=[JoinDef(join_id="j1", to_node="c", from_branches=["nonexistent_branch"])],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "join_source_exists" for v in report.errors)

    def test_unsupported_merge_strategy(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            joins=[JoinDef(join_id="j1", to_node="c", from_branches=[],
                           merge_strategy="telepathy")],
        ))
        assert any(v.invariant_id == "merge_strategy_supported" for v in report.warnings)

    def test_unsupported_merge_strategy_strict_is_error(self):
        """In strict governance, unsupported merge_strategy blocks execution."""
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_blueprint(_make_blueprint(
            joins=[JoinDef(join_id="j1", to_node="c", from_branches=[],
                           merge_strategy="telepathy")],
        ))
        assert not report.is_valid
        assert any(
            v.invariant_id == "merge_strategy_supported" and v.severity == "error"
            for v in report.errors
        )

    def test_unsupported_wait_for(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="mostly")],
        ))
        assert any(v.invariant_id == "wait_for_supported" for v in report.warnings)


class TestLoopInvariants:
    def test_missing_loop_node(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            loops=[LoopDef(loop_id="l1", entry_condition="x", exit_condition="y",
                           path=["a", "b", "ghost"])],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "loop_target_exists" for v in report.errors)

    def test_zero_max_iterations(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            loops=[LoopDef(loop_id="l1", entry_condition="x", exit_condition="y",
                           path=["a", "b"], max_iterations=0)],
        ))
        assert not report.is_valid
        assert any(v.invariant_id == "loop_max_iterations_positive" for v in report.errors)

    def test_loop_bookend_warning(self):
        report = InvariantEngine().check_runtime(_make_blueprint(
            nodes=[
                NodeDef(node_id="sqe", node_type="test", position=1),
                NodeDef(node_id="cs", node_type="test", position=2),
                NodeDef(node_id="st", node_type="test", position=3),
            ],
            connections=[
                ConnectionDef(from_node="sqe", from_port="out", to_node="cs", to_port="in"),
                ConnectionDef(from_node="cs", from_port="out", to_node="st", to_port="in"),
            ],
            loops=[LoopDef(loop_id="l1", entry_condition="x", exit_condition="y",
                           path=["sqe", "cs", "st", "sqe"])],
        ), {})
        assert any(v.invariant_id == "loop_path_redundant_bookend" for v in report.warnings)

    def test_short_loop_path_warning(self):
        report = InvariantEngine().check_runtime(_make_blueprint(
            loops=[LoopDef(loop_id="l1", entry_condition="x", exit_condition="y",
                           path=["a"])],
        ), {})
        assert any(v.invariant_id == "loop_path_minimum_length" for v in report.warnings)


class TestOrphanDetection:
    def test_orphan_node_warning(self):
        report = InvariantEngine().check_blueprint(_make_blueprint(
            nodes=[
                NodeDef(node_id="a", node_type="test", position=1),
                NodeDef(node_id="b", node_type="test", position=2),
                NodeDef(node_id="lonely", node_type="test", position=99),
            ],
            connections=[
                ConnectionDef(from_node="a", from_port="out", to_node="b", to_port="in"),
            ],
        ))
        orphans = [v for v in report.violations if v.invariant_id == "no_orphan_nodes"]
        assert len(orphans) == 1
        assert orphans[0].node_id == "lonely"


# ═══════════════════════════════════════════════════════════════════
# Governance invariants (check_runtime)
# ═══════════════════════════════════════════════════════════════════

class TestGovernancePolicyCoverage:
    def test_model_access_policy_missing(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"model_required": True}},
            policies=[],
        )
        assert any(v.invariant_id == "model_access_policy_coverage" for v in report.warnings)

    def test_model_access_policy_present(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"model_required": True}},
            policies=[{"type": "model_access"}],
        )
        assert not any(v.invariant_id == "model_access_policy_coverage" for v in report.violations)

    def test_tool_access_policy_missing(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"can_call_tools": True}},
            policies=[],
        )
        assert any(v.invariant_id == "tool_access_policy_coverage" for v in report.warnings)

    def test_memory_governance_missing(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"can_write_memory": True}},
            policies=[],
        )
        assert any(v.invariant_id == "memory_governance_coverage" for v in report.warnings)

    def test_no_policies_arg_skips_governance(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"model_required": True, "can_call_tools": True, "can_write_memory": True}},
        )
        gov = [v for v in report.violations if v.invariant_id.endswith("_policy_coverage")]
        assert len(gov) == 0

    def test_review_gate_without_policy(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                gates=[GateDef(gate_id="g1", trigger="test", allowed_decisions=["approve"])],
            ),
            {},
            policies=[],
        )
        assert any(v.invariant_id == "review_gate_policy_coverage" for v in report.warnings)


# ═══════════════════════════════════════════════════════════════════
# Side-effect declaration invariants
# ═══════════════════════════════════════════════════════════════════

class TestSideEffectDeclarations:
    def test_memory_write_must_declare_side_effect(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"can_write_memory": True, "side_effects": []}},
            policies=[{"type": "memory_access"}],
        )
        assert any(v.invariant_id == "memory_write_side_effect_declaration" for v in report.warnings)

    def test_memory_write_with_declaration_ok(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"can_write_memory": True, "side_effects": ["memory_write"]}},
            policies=[{"type": "memory_access"}],
        )
        assert not any(v.invariant_id == "memory_write_side_effect_declaration"
                       for v in report.violations)

    def test_has_side_effects_without_declaration(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"has_side_effects": True}},
            policies=[],
        )
        assert any(v.invariant_id == "side_effect_declaration_required" for v in report.warnings)

    def test_side_effect_policy_coverage(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"side_effects": ["api_call", "search"]}},
            policies=[],
        )
        assert any(v.invariant_id == "side_effect_policy_coverage" for v in report.warnings)

    def test_side_effect_policy_coverage_ok(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"side_effects": ["api_call"]}},
            policies=[{"type": "tool_access"}],
        )
        assert not any(v.invariant_id == "side_effect_policy_coverage"
                       for v in report.violations)

    def test_memory_side_effect_needs_memory_policy(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(),
            {"a": {"can_write_memory": True, "side_effects": ["memory_write"]}},
            policies=[],
        )
        gov = [v for v in report.violations if v.invariant_id == "memory_governance_coverage"]
        se = [v for v in report.violations if v.invariant_id == "side_effect_policy_coverage"]
        assert len(gov) > 0
        assert len(se) > 0


# ═══════════════════════════════════════════════════════════════════
# Cancellation policy for wait_for=any
# ═══════════════════════════════════════════════════════════════════

class TestCancellationPolicy:
    def test_wait_for_any_without_cancellation(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="any")],
            ),
            {},
        )
        assert any(v.invariant_id == "wait_for_any_cancellation_policy"
                   for v in report.warnings)

    def test_wait_for_any_with_valid_cancellation(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="any")],
            ),
            {},
            cancellation_policies={"j1": CANCEL_ALLOW_ALL},
        )
        assert not any(v.invariant_id == "wait_for_any_cancellation_policy"
                       for v in report.violations)

    def test_wait_for_all_no_cancellation_needed(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="all")],
            ),
            {},
        )
        assert not any(v.invariant_id == "wait_for_any_cancellation_policy"
                       for v in report.violations)

    def test_invalid_cancellation_policy_value(self):
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="any")],
            ),
            {},
            cancellation_policies={"j1": "telepathic_cancel"},
        )
        assert any(v.invariant_id == "cancellation_policy_value_invalid"
                   for v in report.warnings)

    def test_all_valid_cancellation_policies(self):
        """Every member of the valid set should pass."""
        for policy in VALID_CANCELLATION_POLICIES:
            report = InvariantEngine().check_runtime(
                _make_blueprint(
                    joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="any")],
                ),
                {},
                cancellation_policies={"j1": policy},
            )
            inv = [v for v in report.violations
                   if v.invariant_id in ("wait_for_any_cancellation_policy",
                                          "cancellation_policy_value_invalid")]
            assert len(inv) == 0, f"Policy '{policy}' should be valid"


# ═══════════════════════════════════════════════════════════════════
# Trace audit invariant (explicit metadata)
# ═══════════════════════════════════════════════════════════════════

class TestTraceAuditInvariant:
    def test_trace_required_metadata_without_trace_node(self):
        """trace.required=true without trace node warns."""
        report = InvariantEngine().check_runtime(
            _make_blueprint(trace={"required": True}),
            {},
        )
        assert any(v.invariant_id == "trace_required_terminal_audit" for v in report.warnings)

    def test_trace_required_metadata_with_trace_node_ok(self):
        """trace.required=true WITH trace node passes."""
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                nodes=[
                    NodeDef(node_id="a", node_type="test", position=1),
                    NodeDef(node_id="b", node_type="test", position=2),
                    NodeDef(node_id="trace_collector", node_type="test", position=3),
                ],
                trace={"required": True},
            ),
            {},
        )
        assert not any(v.invariant_id == "trace_required_terminal_audit"
                       for v in report.violations)

    def test_trace_required_with_audit_node_ok(self):
        """audit or reconciler nodes also satisfy trace_required."""
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                nodes=[
                    NodeDef(node_id="a", node_type="test", position=1),
                    NodeDef(node_id="b", node_type="test", position=2),
                    NodeDef(node_id="audit_logger", node_type="test", position=3),
                ],
                trace={"required": True},
            ),
            {},
        )
        assert not any(v.invariant_id == "trace_required_terminal_audit"
                       for v in report.violations)

    def test_no_trace_required_no_warning(self):
        report = InvariantEngine().check_runtime(_make_blueprint(), {})
        assert not any(v.invariant_id == "trace_required_terminal_audit"
                       for v in report.violations)

    def test_backward_compat_invariant_fallback(self):
        """Old-style invariant with 'trace' in ID still works."""
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                invariants=[InvariantDef(
                    invariant_id="trace_completeness",
                    description="All executions must be traced",
                    enforcement="runtime",
                )],
            ),
            {},
        )
        assert any(v.invariant_id == "trace_required_terminal_audit" for v in report.warnings)

    def test_metadata_overrides_invariant_fallback(self):
        """trace.required=true takes priority over invariant-based detection."""
        report = InvariantEngine().check_runtime(
            _make_blueprint(
                trace={"required": True},
                nodes=[
                    NodeDef(node_id="a", node_type="test", position=1),
                    NodeDef(node_id="trace_collector", node_type="test", position=2),
                ],
                connections=[
                    ConnectionDef(from_node="a", from_port="out", to_node="trace_collector", to_port="in"),
                ],
            ),
            {},
        )
        # Should not have trace_required warning (has trace_collector)
        trace_v = [v for v in report.violations if v.invariant_id == "trace_required_terminal_audit"]
        assert len(trace_v) == 0

    def test_strict_mode_escalates_trace_to_error(self):
        """In strict mode, trace_required without audit node is an error."""
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(trace={"required": True}),
            {},
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "trace_required_terminal_audit"]
        assert len(violations) == 1
        assert violations[0].severity == "error"
        assert not report.is_valid


# ═══════════════════════════════════════════════════════════════════
# Strict governance mode
# ═══════════════════════════════════════════════════════════════════

class TestStrictGovernanceMode:
    """Warnings become errors when strict_governance=True."""

    def test_model_access_warning_in_default_mode(self):
        engine = InvariantEngine(strict_governance=False)
        assert engine.governance_severity == "warning"
        report = engine.check_runtime(
            _make_blueprint(),
            {"a": {"model_required": True}},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "model_access_policy_coverage"]
        assert len(violations) == 1
        assert violations[0].severity == "warning"
        assert report.is_valid

    def test_model_access_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        assert engine.governance_severity == "error"
        report = engine.check_runtime(
            _make_blueprint(),
            {"a": {"model_required": True}},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "model_access_policy_coverage"]
        assert len(violations) == 1
        assert violations[0].severity == "error"
        assert not report.is_valid

    def test_tool_access_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(),
            {"a": {"can_call_tools": True}},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "tool_access_policy_coverage"]
        assert violations[0].severity == "error"

    def test_memory_governance_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(),
            {"a": {"can_write_memory": True, "side_effects": ["memory_write"]}},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "memory_governance_coverage"]
        assert violations[0].severity == "error"

    def test_side_effect_declaration_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(),
            {"a": {"has_side_effects": True}},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "side_effect_declaration_required"]
        assert violations[0].severity == "error"

    def test_cancellation_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(
                joins=[JoinDef(join_id="j1", to_node="c", from_branches=[], wait_for="any")],
            ),
            {},
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "wait_for_any_cancellation_policy"]
        assert violations[0].severity == "error"

    def test_review_gate_error_in_strict_mode(self):
        engine = InvariantEngine(strict_governance=True)
        report = engine.check_runtime(
            _make_blueprint(
                gates=[GateDef(gate_id="g1", trigger="test", allowed_decisions=["approve"])],
            ),
            {},
            policies=[],
        )
        violations = [v for v in report.violations
                      if v.invariant_id == "review_gate_policy_coverage"]
        assert violations[0].severity == "error"

    def test_structural_invariants_unaffected_by_strict(self):
        engine = InvariantEngine(strict_governance=False)
        report = engine.check_blueprint(_make_blueprint(
            connections=[
                ConnectionDef(from_node="ghost", from_port="out", to_node="b", to_port="in"),
            ],
        ))
        assert not report.is_valid
        assert all(v.severity == "error" for v in report.errors)

    def test_env_var_strict_mode(self, monkeypatch):
        monkeypatch.setenv("NODECHAIN_GOVERNANCE_STRICT", "1")
        engine = InvariantEngine()
        assert engine.governance_severity == "error"

    def test_env_var_default_mode(self, monkeypatch):
        monkeypatch.delenv("NODECHAIN_GOVERNANCE_STRICT", raising=False)
        engine = InvariantEngine()
        assert engine.governance_severity == "warning"

    def test_explicit_false_overrides_env(self, monkeypatch):
        monkeypatch.setenv("NODECHAIN_GOVERNANCE_STRICT", "1")
        engine = InvariantEngine(strict_governance=False)
        assert engine.governance_severity == "warning"


# ═══════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════

class TestInvariantReport:
    def test_summary_clean(self):
        report = InvariantReport(checks_run=10)
        assert "10 checks" in report.summary()
        assert "All invariants satisfied" in report.summary()

    def test_summary_with_violations(self):
        from nodechain.runtime.invariant_engine import InvariantViolation
        report = InvariantReport(
            checks_run=5,
            violations=[
                InvariantViolation(invariant_id="test", severity="error", message="broken"),
            ],
        )
        assert not report.is_valid
        assert "1 errors" in report.summary()

    def test_warnings_dont_invalidate(self):
        from nodechain.runtime.invariant_engine import InvariantViolation
        report = InvariantReport(
            checks_run=3,
            violations=[
                InvariantViolation(invariant_id="w1", severity="warning", message="meh"),
                InvariantViolation(invariant_id="w2", severity="warning", message="also meh"),
            ],
        )
        assert report.is_valid
        assert len(report.warnings) == 2
        assert len(report.errors) == 0
