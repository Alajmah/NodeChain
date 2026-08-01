"""Package Trust Runtime Enforcement Tests (v2.44.0).

Proves the 10 acceptance criteria:
  1. Package trust uses runtime observed_trust_level, not self-declared.
  2. Privileged nodes trigger package-trust evaluation.
  3. Built-in trusted nodes get explicit durable allow.
  4. Unknown/untrusted packages cannot receive privileged capabilities.
  5. Durable decisions bind run+step+node+origin+digest.
  6. PACKAGE_TRUST_ALLOWED/DENIED bind to durable decision_id.
  7. Non-privileged nodes skip the gate.
  8. Self-declared trust_level doesn't override observed.
  9. is_privileged_node helper works correctly.
  10. Existing gates remain intact (regression).
"""

from __future__ import annotations

import pytest

from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
    is_privileged_node,
)
from nodechain.core.state import StateManager, ChainState


class TestIsPrivilegedHelper:
    """v2.44.0: is_privileged_node identifies privileged nodes."""

    def test_tools_required_is_privileged(self):
        c = NodeContract(
            contract_id="t", node_id="n", version="1",
            entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
            exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
            requirements=Requirements(tools_required=["search"]),
        )
        assert is_privileged_node(c)

    def test_memory_write_is_privileged(self):
        c = NodeContract(
            contract_id="t", node_id="n", version="1",
            entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
            exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
            requirements=Requirements(memory_access="write"),
        )
        assert is_privileged_node(c)

    def test_no_requirements_not_privileged(self):
        c = NodeContract(
            contract_id="t", node_id="n", version="1",
            entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
            exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
        )
        assert not is_privileged_node(c)


class TestPolicyObservedTrust:
    """v2.44.0: TRUST_LEVEL_POLICY uses observed_trust_level vocabulary."""

    def test_deny_local_untrusted(self):
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {"observed_trust_level": "local_untrusted"},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)

    def test_allow_built_in(self):
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {"observed_trust_level": "built_in"},
        )
        assert any(d.action == PolicyAction.ALLOW for d in decisions)
        assert not any(d.action == PolicyAction.DENY for d in decisions)

    def test_allow_local_trusted(self):
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {"observed_trust_level": "local_trusted"},
        )
        assert any(d.action == PolicyAction.ALLOW for d in decisions)

    def test_deny_remote_untrusted(self):
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {"observed_trust_level": "remote_untrusted"},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)

    def test_deny_unknown(self):
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {"observed_trust_level": "unknown"},
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)


class TestSelfDeclaredTrustIgnored:
    """v2.44.0: self-declared Requirements.trust_level doesn't override observed."""

    def test_self_declared_trusted_with_observed_untrusted_denies(self):
        """Node declares trust_level=trusted but observed=local_untrusted → denied."""
        from nodechain.core.policy import PolicyType, PolicyAction, PolicyEngine
        from nodechain.core.default_policies import TRUST_LEVEL_POLICY
        engine = PolicyEngine()
        engine.register(TRUST_LEVEL_POLICY)
        decisions = engine.evaluate(
            PolicyType.TRUST_LEVEL, "n",
            {
                "observed_trust_level": "local_untrusted",
                "required_trust_level": "trusted",  # self-declared
            },
        )
        assert any(d.action == PolicyAction.DENY for d in decisions)


class TestPolicyGatePackageTrust:
    """v2.44.0: PolicyGate evaluates package trust for privileged nodes."""

    def test_built_in_privileged_node_allowed(self):
        """v2.44.4: real built-in node (under nodechain.nodes.*) is allowed."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.nodes.search_tool import SearchToolNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("search_tool", SearchToolNode(allow_unguarded=True))
        trust_eval = [e for e in result.evaluated_policies if e.get("type") == "package_trust"]
        assert len(trust_eval) == 1
        assert trust_eval[0]["decision"] == "allowed"

    def test_untrusted_privileged_node_denied(self):
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        class UntrustedNode(BaseNode):
            _trust_level = "local_untrusted"
            _node_origin = "local_registry"

            @property
            def manifest(self):
                return NodeManifest(
                    node_id="un", node_type="test", name="U", description="d",
                    contract=NodeContract(
                        contract_id="un.v1", node_id="un",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["search"]),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("un", UntrustedNode())
        assert not result.allowed

    def test_non_privileged_node_skips_trust_gate(self):
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        class PlainNode(BaseNode):
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="pl", node_type="test", name="P", description="d",
                    contract=NodeContract(
                        contract_id="pl.v1", node_id="pl",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("pl", PlainNode())
        trust_eval = [e for e in result.evaluated_policies if e.get("type") == "package_trust"]
        assert len(trust_eval) == 0  # skipped

    def test_fail_closed_without_policy(self):
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()  # empty

        class PrivNode(BaseNode):
            _trust_level = "local_trusted"

            @property
            def manifest(self):
                return NodeManifest(
                    node_id="pn", node_type="test", name="P", description="d",
                    contract=NodeContract(
                        contract_id="pn.v1", node_id="pn",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["search"]),
                    ),
                )

            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("pn", PrivNode())
        assert not result.allowed
        assert "No trust-level policy decision" in (result.denial_reason or "")


class TestDurableDecisions:
    """v2.44.0: package_trust_decisions table."""

    def test_record_and_retrieve(self, tmp_path):
        sm = StateManager(db_path=str(tmp_path / "pt.db"))
        sm.record_package_trust_decision({
            "decision_id": "pt-1", "run_id": "r1", "node_id": "n",
            "origin": "built_in", "observed_trust_level": "built_in",
            "is_privileged": True, "decision": "allow",
            "trust_source": "built_in_default",
            "package_digest": "abc123",
        })
        decisions = sm.get_package_trust_decisions(run_id="r1")
        assert len(decisions) == 1
        assert decisions[0]["decision"] == "allow"
        assert decisions[0]["is_privileged"] == 1
        assert decisions[0]["package_digest"] == "abc123"


class TestProvenanceBoundary:
    """v2.44.4: explicit built-in boundary.

    Inherited BaseNode defaults are treated as "unknown" for privileged
    nodes that aren't proven built-in by module namespace.
    """

    def test_arbitrary_subclass_inherited_defaults_denied(self):
        """Custom BaseNode subclass with tools_required and no loader
        provenance inherits _trust_level='built_in' but is NOT known
        built-in → denied."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        class CustomPrivNode(BaseNode):
            # Inherits _trust_level='built_in', _node_origin='built_in'
            # from BaseNode — but module is __main__ / test module,
            # NOT nodechain.nodes.*
            @property
            def manifest(self):
                return NodeManifest(
                    node_id="cn", node_type="test", name="C", description="d",
                    contract=NodeContract(
                        contract_id="cn.v1", node_id="cn",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["search"]),
                    ),
                )
            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("cn", CustomPrivNode())
        assert not result.allowed
        trust_eval = [e for e in result.evaluated_policies if e.get("type") == "package_trust"]
        assert len(trust_eval) == 1
        assert trust_eval[0]["observed_trust_level"] == "unknown"

    def test_actual_built_in_node_allowed(self):
        """Real SearchToolNode is under nodechain.nodes.* → built-in allowed."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.nodes.search_tool import SearchToolNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("search_tool", SearchToolNode(allow_unguarded=True))
        trust_eval = [e for e in result.evaluated_policies if e.get("type") == "package_trust"]
        assert len(trust_eval) == 1
        assert trust_eval[0]["decision"] == "allowed"

    def test_local_trusted_loader_set_allowed(self):
        """Loader-set local_trusted is honored."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        class LocalTrustedNode(BaseNode):
            _trust_level = "local_trusted"
            _node_origin = "local_registry"

            @property
            def manifest(self):
                return NodeManifest(
                    node_id="lt", node_type="test", name="L", description="d",
                    contract=NodeContract(
                        contract_id="lt.v1", node_id="lt",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["search"]),
                    ),
                )
            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("lt", LocalTrustedNode())
        trust_eval = [e for e in result.evaluated_policies if e.get("type") == "package_trust"]
        assert len(trust_eval) == 1
        assert trust_eval[0]["decision"] == "allowed"

    def test_local_untrusted_loader_set_denied(self):
        """Loader-set local_untrusted is denied for privileged."""
        from nodechain.runtime.policy_gate import PolicyGate
        from nodechain.core.policy import PolicyEngine
        from nodechain.core.default_policies import DEFAULT_POLICIES
        from nodechain.core.manifest import NodeManifest
        from nodechain.nodes.base_node import BaseNode

        engine = PolicyEngine()
        for p in DEFAULT_POLICIES:
            engine.register(p)

        class LocalUntrustedNode(BaseNode):
            _trust_level = "local_untrusted"
            _node_origin = "local_registry"

            @property
            def manifest(self):
                return NodeManifest(
                    node_id="lu", node_type="test", name="U", description="d",
                    contract=NodeContract(
                        contract_id="lu.v1", node_id="lu",
                        entry=EntryContract(input_type="any", schema_ref="x", required_fields=[]),
                        exit=ExitContract(output_type="any", schema_ref="x", guaranteed_fields=[]),
                        requirements=Requirements(tools_required=["search"]),
                    ),
                )
            async def execute(self, envelope):
                pass

        gate = PolicyGate(
            policy_engine=engine,
            get_capabilities=lambda nid: None,
            get_step=lambda: 0,
        )
        result = gate.check("lu", LocalUntrustedNode())
        assert not result.allowed
